// Uniform way to open a page in different browsers for the test runners.
//
// Browser specs:
//   pw:chromium | pw:firefox | pw:webkit   Playwright's bundled engine builds
//   pw-channel:chrome | pw-channel:msedge  installed Google Chrome / Microsoft Edge via Playwright
//   wd:<name>@<driver-url>                 a real installed browser via its W3C WebDriver
//                                          (e.g. wd:firefox@http://127.0.0.1:4444 with geckodriver,
//                                           wd:safari@http://127.0.0.1:4445 with safaridriver)
//
// Runners only observe pages. Nothing here intercepts, rewrites or fulfills
// network requests, and no browser security setting is changed.

import { createRequire } from 'node:module';
import { platform, release } from 'node:os';
import { chromium, firefox, webkit } from 'playwright';

const ENGINES = { chromium, firefox, webkit };

export function parseSpec(spec) {
  if (spec.startsWith('pw:')) return { driver: 'playwright', engine: spec.slice(3) };
  if (spec.startsWith('pw-channel:')) return { driver: 'playwright', engine: 'chromium', channel: spec.slice(11) };
  if (spec.startsWith('wd:')) {
    const [name, url] = spec.slice(3).split('@');
    return { driver: 'webdriver', name, url };
  }
  throw new Error(`unknown browser spec ${spec}`);
}

export async function openBrowser(spec, { userDataDir, launchArgs = [], proxy } = {}) {
  const s = parseSpec(spec);
  return s.driver === 'playwright' ? openPlaywright(spec, s, { userDataDir, launchArgs, proxy }) : openWebDriver(spec, s, { userDataDir });
}

async function openPlaywright(spec, s, { userDataDir, launchArgs, proxy }) {
  const type = ENGINES[s.engine];
  if (!type) throw new Error(`unknown engine ${s.engine}`);
  const options = {
    headless: true,
    ...(s.channel ? { channel: s.channel } : {}),
    ...(launchArgs.length && s.engine === 'chromium' ? { args: launchArgs } : {}),
    ...(proxy ? { proxy } : {}),
  };
  let browser;
  let context;
  if (userDataDir) {
    context = await type.launchPersistentContext(userDataDir, options);
    browser = context.browser();
  } else {
    browser = await type.launch(options);
    context = await browser.newContext();
  }
  const version = browser ? browser.version() : 'unknown (persistent context)';
  return {
    spec,
    driver: 'playwright',
    engine: s.engine,
    channel: s.channel ?? null,
    version,
    context,
    async open(url) {
      const page = await context.newPage();
      const consoleLines = [];
      page.on('console', (m) => consoleLines.push({ type: m.type(), text: m.text() }));
      page.on('pageerror', (e) => consoleLines.push({ type: 'pageerror', text: e.message }));
      await page.goto(url);
      // Playwright eval()s *string* expressions inside the page, which the
      // app's CSP (no 'unsafe-eval') rightly blocks; passing a function goes
      // through DevTools instead and is unaffected by page CSP.
      const fn = (expr) => new Function(`return (${expr});`);
      return {
        page,
        console: consoleLines,
        evaluate: (expr) => page.evaluate(fn(expr)),
        waitFor: (expr, timeoutMs) =>
          page.waitForFunction(fn(expr), null, { timeout: timeoutMs, polling: 250 }),
        close: () => page.close(),
      };
    },
    /** Top-level navigation; returns the browser's own error for failures. */
    async navigate(url, timeoutMs = 30_000) {
      const page = await context.newPage();
      try {
        const res = await page.goto(url, { timeout: timeoutMs });
        return { ok: true, status: res?.status() ?? null };
      } catch (err) {
        return { ok: false, error: String(err.message).split('\n')[0] };
      } finally {
        await page.close();
      }
    },
    async close() {
      await context.close();
      if (browser && !userDataDir) await browser.close();
    },
  };
}

async function wd(url, method, path, body) {
  const res = await fetch(`${url}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.value?.error) {
    throw new Error(`WebDriver ${method} ${path}: ${res.status} ${JSON.stringify(json.value ?? json).slice(0, 500)}`);
  }
  return json.value;
}

async function openWebDriver(spec, s, { userDataDir }) {
  const alwaysMatch = { browserName: s.name };
  if (s.name === 'firefox') {
    alwaysMatch['moz:firefoxOptions'] = {
      args: ['-headless', ...(userDataDir ? ['-profile', userDataDir] : [])],
    };
  }
  // safaridriver can time out launching Safari on the first session right after
  // `safaridriver --enable` (a cold start: "session not created ... timed out
  // ... launching a compatible local Safari"). Later sessions in the same run
  // succeed, so retry session creation a few times before giving up.
  let session;
  for (let attempt = 1; ; attempt++) {
    try {
      session = await wd(s.url, 'POST', '/session', { capabilities: { alwaysMatch } });
      break;
    } catch (err) {
      if (attempt >= 5) throw err;
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  const id = session.sessionId;
  // The default page-load timeout (300 s) equals Node fetch's response-header
  // timeout, so a navigation that never commits (e.g. a download) could make
  // the client give up first; a shorter driver timeout always answers first.
  await wd(s.url, 'POST', `/session/${id}/timeouts`, { pageLoad: 60_000 }).catch(() => {});
  const caps = session.capabilities ?? {};
  const exec = (expr) => wd(s.url, 'POST', `/session/${id}/execute/sync`, {
    script: `return (${expr});`,
    args: [],
  });
  return {
    spec,
    driver: 'webdriver',
    engine: s.name,
    channel: null,
    version: `${caps.browserName ?? s.name} ${caps.browserVersion ?? '?'} on ${caps.platformName ?? '?'}`,
    capabilities: caps,
    async open(url) {
      await wd(s.url, 'POST', `/session/${id}/url`, { url });
      return {
        console: [],
        evaluate: exec,
        async waitFor(expr, timeoutMs) {
          const deadline = Date.now() + timeoutMs;
          for (;;) {
            if (await exec(expr)) return;
            if (Date.now() > deadline) throw new Error(`timeout waiting for ${expr}`);
            await new Promise((r) => setTimeout(r, 500));
          }
        },
        close: async () => {},
      };
    },
    /** Top-level navigation from about:blank. W3C WebDriver should report
     *  TLS certificate rejections as the error "insecure certificate"; some
     *  drivers (safaridriver) instead return success while the browser shows
     *  its own warning page, so we also record whether the target host was
     *  actually reached (the committed URL left about:blank for it). */
    async navigate(url) {
      const target = new URL(url).host;
      await wd(s.url, 'POST', `/session/${id}/url`, { url: 'about:blank' }).catch(() => {});
      let res;
      try {
        res = await fetch(`${s.url}/session/${id}/url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        });
      } catch (err) {
        return { ok: false, reached: false, error: `WebDriver request failed: ${err.cause?.code ?? err.message}` };
      }
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.value?.error) {
        const message = String(json.value?.message ?? '').split('\n')[0];
        return { ok: false, reached: false, error: `${json.value?.error ?? res.status}${message ? `: ${message}` : ''}` };
      }
      let landed = null;
      for (let i = 0; i < 10; i++) {
        landed = await wd(s.url, 'GET', `/session/${id}/url`).catch(() => null);
        if (landed && landed !== 'about:blank') break;
        await new Promise((r) => setTimeout(r, 500));
      }
      const title = await wd(s.url, 'GET', `/session/${id}/title`).catch(() => null);
      let reached = false;
      try {
        reached = new URL(landed).host === target;
      } catch {}
      const interstitial = /not private|certificate|isn.t secure|not secure/i.test(String(title));
      if (reached && !interstitial) return { ok: true, reached, title, landed_url: landed };
      return {
        ok: false,
        reached,
        title,
        landed_url: landed,
        error: interstitial
          ? `browser certificate warning page: "${title}"`
          : `navigation did not reach ${target} (committed URL: ${landed})`,
      };
    },
    async close() {
      await wd(s.url, 'DELETE', `/session/${id}`).catch(() => {});
    },
  };
}

/** Versions of the tooling around the browser, recorded with every result. */
export function toolVersions() {
  return {
    node: process.version,
    playwright: createRequire(import.meta.url)('playwright/package.json').version,
    os: `${platform()} ${release()}`,
    // Set on GitHub-hosted runners (e.g. "ubuntu24 20260921.1").
    runner_image: process.env.ImageOS ? `${process.env.ImageOS} ${process.env.ImageVersion ?? '?'}` : null,
  };
}

export function specSlug(spec) {
  return spec.replace(/@.*$/, '').replace(/[^a-z0-9]+/gi, '-');
}

export function browserArgs(argv, fallback) {
  const specs = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === '--browser') specs.push(argv[i + 1]);
  return specs.length ? specs : fallback;
}
