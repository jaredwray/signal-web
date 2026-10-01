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
  const session = await wd(s.url, 'POST', '/session', { capabilities: { alwaysMatch } });
  const id = session.sessionId;
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
    async close() {
      await wd(s.url, 'DELETE', `/session/${id}`).catch(() => {});
    },
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
