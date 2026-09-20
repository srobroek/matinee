use std::sync::Arc;

use matinee_daemon::lifecycle::Daemon;
use matinee_mcp::Adapter;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

fn daemon() -> Arc<Daemon> {
    let path = std::env::temp_dir().join(format!("matinee-mcp-test-{}", Uuid::now_v7()));
    Arc::new(Daemon::start(path).expect("start test daemon"))
}

async fn exchange(adapter: Arc<Adapter>, requests: &[Value]) -> Vec<Value> {
    let (client, server) = tokio::io::duplex(128 * 1024);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);
    let task = tokio::spawn(async move {
        adapter
            .serve(BufReader::new(server_read), server_write)
            .await
            .expect("serve MCP pipe");
    });
    for request in requests {
        let mut line = serde_json::to_vec(request).expect("encode request");
        line.push(b'\n');
        client_write.write_all(&line).await.expect("write request");
    }
    client_write.shutdown().await.expect("close request stream");
    let mut bytes = Vec::new();
    client_read
        .read_to_end(&mut bytes)
        .await
        .expect("read responses");
    task.await.expect("join adapter");
    String::from_utf8(bytes)
        .expect("responses are UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("response is JSON"))
        .collect()
}

#[tokio::test]
async fn protocol_errors_keep_the_pipe_open_and_tools_are_exactly_bounded() {
    let adapter = Arc::new(Adapter::new(daemon(), Uuid::now_v7()));
    let responses = exchange(
        adapter,
        &[
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            Value::String("malformed-by-type".to_owned()),
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "unknown", "arguments": {}}}),
        ],
    )
    .await;

    assert_eq!(responses.len(), 4);
    let instance = responses[0]["result"]["daemon_instance_id"]
        .as_str()
        .expect("initialize identity");
    assert_eq!(responses[0]["daemon_instance_id"], instance);
    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("tool list");
    assert_eq!(tools.len(), 10);
    let names: Vec<_> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "browser_list",
            "session_open",
            "session_get",
            "session_close",
            "page_observe",
            "page_navigate",
            "element_click",
            "element_type",
            "page_screenshot",
            "request_get",
        ]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["inputSchema"]["properties"].is_object());
    }
    assert_eq!(responses[2]["error"]["code"], -32600);
    assert_eq!(responses[3]["error"]["code"], -32602);
}

#[tokio::test]
async fn missing_mutation_context_is_rejected_before_dispatch() {
    let daemon = daemon();
    let adapter = Arc::new(Adapter::new(Arc::clone(&daemon), Uuid::now_v7()));
    let responses = exchange(
        adapter,
        &[json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "session_open", "arguments": {"candidate_revision": "fixture-revision-1"}}
        })],
    )
    .await;
    assert_eq!(responses[0]["error"]["code"], -32602);
    assert_eq!(
        daemon
            .registry()
            .dispatched_count()
            .expect("dispatch count"),
        0
    );
}

#[tokio::test]
async fn stale_instance_identity_names_the_unobserved_action_sequence() {
    let adapter = Arc::new(Adapter::new(daemon(), Uuid::now_v7()));
    let responses = exchange(
        adapter,
        &[json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "daemon_instance_id": "00000000-0000-0000-0000-000000000000",
            "last_action_sequence": 17,
            "params": {"name": "browser_list", "arguments": {}}
        })],
    )
    .await;
    assert_eq!(
        responses[0]["error"]["data"]["failure"]["code"],
        "daemon.restarted"
    );
    assert!(
        responses[0]["error"]["data"]["failure"]["detail"]
            .as_str()
            .expect("failure detail")
            .contains("17")
    );
}
