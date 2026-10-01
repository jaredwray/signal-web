// Same-origin frame that tries to become the active "tab"; it must be refused
// while another context holds the lock (see storage-test.js).
import { acquireTabLock } from './lib/tablock.js';

acquireTabLock().then((acquired) => parent.postMessage({ tablockAcquired: acquired }, location.origin));
