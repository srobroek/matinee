//! Serves the deterministic MVP fixture on a chosen port.
//!
//! ```bash
//! cargo run -p matinee-fixture --example serve -- 8787
//! ```

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8787);
    let (address, server) = matinee_fixture::bind_and_serve(port)
        .await
        .expect("bind fixture");
    println!("fixture listening on http://{address}/alpha");
    server
        .await
        .expect("join fixture server")
        .expect("serve fixture");
}
