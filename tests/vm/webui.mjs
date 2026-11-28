// A headless Chromium in the lab container, driven over the DevTools protocol, for Anaconda's web interface: what a
// person sees and clicks in the installer, reached through a port QEMU forwards to the installer's system (iso.mjs).
// Chromium is the lab's (chromium-headless, Containerfile); Node's own WebSocket speaks to it, so nothing comes from npm.
import { spawn } from 'node:child_process';
import fs from 'node:fs';

const BROWSERS = ['/usr/lib64/chromium-browser/headless_shell', '/usr/bin/chromium-browser', '/usr/bin/chromium'];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function browser(profile) {
  const bin = BROWSERS.find((b) => fs.existsSync(b));
  if (!bin) throw new Error(`webui.mjs: no Chromium in the lab (${BROWSERS.join(', ')})`);
  fs.rmSync(profile, { recursive: true, force: true });
  fs.mkdirSync(profile, { recursive: true });
  // The lab runs as root in its container, where Chromium's sandbox cannot start
  const proc = spawn(bin, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--ignore-certificate-errors',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--window-size=1280,800', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let log = '';
  const endpoint = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`webui.mjs: Chromium gave no DevTools endpoint\n${log}`)), 60000);
    proc.stderr.on('data', (data) => {
      log = `${log}${data}`.slice(-8000);
      const m = log.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    });
    proc.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`webui.mjs: Chromium ended (${code})\n${log}`));
    });
  });

  const ws = new WebSocket(endpoint);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error(`webui.mjs: no connection to ${endpoint}`));
  });
  let lastId = 0;
  const pending = new Map();
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    const waiting = message.id && pending.get(message.id);
    if (!waiting) return;
    pending.delete(message.id);
    if (message.error) waiting.reject(new Error(`${waiting.method}: ${message.error.message}`));
    else waiting.resolve(message.result);
  };
  ws.onclose = () => {
    for (const waiting of pending.values()) waiting.reject(new Error(`${waiting.method}: Chromium closed the connection`));
    pending.clear();
  };
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++lastId;
    pending.set(id, { method, resolve, reject });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  const page = (method, params) => send(method, params, sessionId);

  // An expression evaluated in the page, awaited, its value returned
  async function evaluate(expression) {
    const r = await page('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`${r.exceptionDetails.exception?.description || r.exceptionDetails.text}\n  in ${expression.slice(0, 200)}`);
    return r.result.value;
  }
  // Until the expression is true, or the time is up: then an error naming what was waited for
  async function until(expression, what, seconds = 120) {
    let last = '';
    for (const end = Date.now() + seconds * 1000; Date.now() < end; await sleep(500)) {
      try {
        const v = await evaluate(expression);
        if (v) return v;
      } catch (error) {
        // The page is between two documents, or not there yet
        last = error.message;
      }
    }
    throw new Error(`waited ${seconds} s for ${what}${last ? `\n  ${last}` : ''}`);
  }
  const q = (selector) => `document.querySelector(${JSON.stringify(selector)})`;
  // Present, shown and not disabled, as a person can click it
  const usable = (selector) => `(() => { const e = ${q(selector)}; return Boolean(e && e.getClientRects().length && !e.disabled && e.getAttribute('aria-disabled') !== 'true'); })()`;
  async function click(selector, what = selector, seconds = 120) {
    await until(usable(selector), what, seconds);
    // A menu item's id is on its <li>, the handler on the button inside
    await evaluate(`(() => { const e = ${q(selector)}; const b = e.matches('li') ? (e.querySelector('button, input') || e) : e; b.scrollIntoView({ block: 'center' }); b.click(); })()`);
  }
  // The button inside scope whose words are label, for the buttons that have no id
  async function clickButton(scope, label, what = label, seconds = 120) {
    const find = `[...document.querySelectorAll(${JSON.stringify(`${scope} button`)})].find((e) => e.textContent.trim() === ${JSON.stringify(label)})`;
    await until(`(() => { document.querySelectorAll('[data-lab]').forEach((e) => e.removeAttribute('data-lab')); const b = ${find}; if (b) b.setAttribute('data-lab', 'target'); return Boolean(b); })()`, what, seconds);
    await click('button[data-lab="target"]', what, seconds);
  }
  // Typed, as keys reach a focused field: React sees each change. Whatever the field held is replaced
  async function type(selector, text, what = selector) {
    await until(usable(selector), what);
    await evaluate(`(() => { const e = ${q(selector)}; const i = e.matches('input, textarea') ? e : e.querySelector('input, textarea'); i.focus(); i.select(); })()`);
    await page('Input.insertText', { text });
  }
  async function shot(target) {
    try {
      const { data } = await page('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(target, Buffer.from(data, 'base64'));
    } catch {
      // Nothing to take
    }
  }
  async function close() {
    await send('Browser.close').catch(() => {});
    ws.close();
    if (proc.exitCode === null) proc.kill();
  }
  return {
    goto: (url) => page('Page.navigate', { url }),
    evaluate, until, usable, click, clickButton, type, shot, close, q,
  };
}
