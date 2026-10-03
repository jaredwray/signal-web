// Single-active-tab guard using the Web Locks API.
//
// Protocol state (ratchets, prekeys) must have exactly one writer; two tabs
// decrypting with the same stored session would fork it. The first tab to
// call acquireTabLock() holds the lock until it closes.
//
// Resolves to one of:
//   'acquired'        this context now holds the lock
//   'held-elsewhere'  another same-origin context holds it
//   'unavailable'     the browser has no Web Locks API
//   'error'           the request failed (reason in the console)
// Only 'held-elsewhere' means another tab is open; callers must not treat
// 'unavailable' or 'error' as that.
export function acquireTabLock(name = 'signal-web-active-tab') {
  if (!navigator.locks?.request) return Promise.resolve('unavailable');
  return new Promise((resolve) => {
    navigator.locks
      .request(name, { ifAvailable: true }, (lock) => {
        resolve(lock ? 'acquired' : 'held-elsewhere');
        if (!lock) return undefined;
        return new Promise(() => {}); // held for the lifetime of this tab
      })
      .catch((err) => {
        console.error('Web Locks request failed', err);
        resolve('error');
      });
  });
}
