"use strict";

/**
 * Spawns engine-main.js on a free loopback port for black-box endpoint tests.
 * Tray, idle quit and protocol registration stay off.
 */
const http = require("http");
const net = require("net");
const path = require("path");
const { spawn } = require("child_process");

const ENGINE = path.join(__dirname, "..", "engine-main.js");
const ALLOWED_ORIGIN = "http://localhost:3000";

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/** Plain http.request so tests can send browser-only headers such as Origin. */
function request(port, pathname, { method = "GET", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: pathname, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const body = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body, text: body.toString("utf8") });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function waitForHealth(port, child, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode != null) throw new Error(`engine exited early (${child.exitCode})`);
    try {
      const res = await request(port, "/health");
      if (res.status === 200) return;
    } catch {
      /* not listening yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("engine did not become healthy");
}

async function startEngine(env = {}) {
  const port = await freePort();
  const child = spawn(process.execPath, [ENGINE], {
    env: {
      ...process.env,
      NEXUSHUB_PROXY_PORT: String(port),
      NEXUSHUB_ENGINE_TRAY: "0",
      NEXUSHUB_ENGINE_STAY: "1",
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (c) => (log += c));
  child.stderr.on("data", (c) => (log += c));
  await waitForHealth(port, child);

  const info = await request(port, "/engine", { headers: { Origin: ALLOWED_ORIGIN } });
  const token = JSON.parse(info.text).sessionToken;

  return {
    port,
    token,
    log: () => log,
    request: (pathname, opts) => request(port, pathname, opts),
    stop: () =>
      new Promise((resolve) => {
        if (child.exitCode != null) return resolve();
        child.once("exit", () => resolve());
        child.kill();
      }),
  };
}

module.exports = { ALLOWED_ORIGIN, freePort, request, startEngine };
