// Single-active-tab guard using the Web Locks API.
//
// Protocol state (ratchets, prekeys) must have exactly one writer; two tabs
// decrypting with the same stored session would fork it. The first tab to
// call acquireTabLock() holds the lock until it closes; later tabs get false.
export function acquireTabLock(name = 'signal-web-active-tab') {
  if (!navigator.locks) return Promise.resolve(false);
  return new Promise((resolve) => {
    navigator.locks
      .request(name, { ifAvailable: true }, (lock) => {
        resolve(Boolean(lock));
        if (!lock) return undefined;
        return new Promise(() => {}); // held for the lifetime of this tab
      })
      .catch(() => resolve(false));
  });
}
