const DATABASE_NAME = "matinee-extension-keys-v1";
const STORE_NAME = "keys";
const KEY_REFERENCE = "extension-identity";

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onerror = () => reject(request.error ?? new Error("key database open failed"));
    request.onsuccess = () => resolve(request.result);
  });
}

function transact(mode, operation) {
  return openDatabase().then((database) => new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, mode);
    const store = transaction.objectStore(STORE_NAME);
    let value;
    transaction.oncomplete = () => {
      database.close();
      resolve(value);
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error ?? new Error("key database transaction failed"));
    };
    transaction.onabort = () => {
      database.close();
      reject(transaction.error ?? new Error("key database transaction aborted"));
    };
    try {
      operation(store, (result) => { value = result; });
      if (mode === "readwrite" && typeof transaction.commit === "function") transaction.commit();
    } catch (error) {
      try { transaction.abort(); } catch {}
      reject(error);
    }
  }));
}

export function storeIdentityKey(privateKey, publicKey, fingerprint) {
  return transact("readwrite", (store) => {
    store.put({ version: 1, privateKey, publicKey, fingerprint }, KEY_REFERENCE);
  });
}

export function loadIdentityKey() {
  return transact("readonly", (store, setValue) => {
    const request = store.get(KEY_REFERENCE);
    request.onsuccess = () => setValue(request.result);
  });
}

export function clearIdentityKey() {
  return transact("readwrite", (store) => {
    store.delete(KEY_REFERENCE);
  });
}
