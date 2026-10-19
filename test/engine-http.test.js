"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { ALLOWED_ORIGIN, startEngine } = require("./helpers");

let engine;
test.before(async () => {
  engine = await startEngine();
});
test.after(async () => {
  if (engine) await engine.stop();
});

const enc = encodeURIComponent;

test("/health is unauthenticated and identifies the engine", async () => {
  const res = await engine.request("/health?json=1");
  assert.equal(res.status, 200);
  const body = JSON.parse(res.text);
  assert.equal(body.ok, true);
  assert.equal(body.role, "local-stream-proxy");
});

test("/engine only issues the session token to allowlisted origins", async () => {
  assert.match(engine.token, /^[0-9a-f]{64}$/);
  const noOrigin = JSON.parse((await engine.request("/engine")).text);
  assert.equal(noOrigin.sessionToken, undefined);
  const evil = JSON.parse((await engine.request("/engine", { headers: { Origin: "https://evil.example" } })).text);
  assert.equal(evil.sessionToken, undefined);
});

test("/proxy requires the session token", async () => {
  const res = await engine.request(`/proxy?url=${enc("https://1.1.1.1/")}`);
  assert.equal(res.status, 403);
  assert.match(res.text, /session token/);
});

test("/proxy rejects disallowed origins even with a valid token", async () => {
  const res = await engine.request(`/proxy?url=${enc("https://1.1.1.1/")}&token=${engine.token}`, {
    headers: { Origin: "https://evil.example" },
  });
  assert.equal(res.status, 403);
});

test("/proxy refuses loopback upstreams", async () => {
  const self = `http://127.0.0.1:${engine.port}/health`;
  const res = await engine.request(`/proxy?url=${enc(self)}&token=${engine.token}`);
  assert.equal(res.status, 502);
  assert.match(res.text, /Blocked destination/);
});

test("/quit is POST + token only", async () => {
  assert.equal((await engine.request("/quit", { method: "GET" })).status, 405);
  const originOnly = await engine.request("/quit", { method: "POST", headers: { Origin: ALLOWED_ORIGIN } });
  assert.equal(originOnly.status, 403);
});

test("CORS preflight from a disallowed origin is refused", async () => {
  const res = await engine.request("/proxy", { method: "OPTIONS", headers: { Origin: "https://evil.example" } });
  assert.equal(res.status, 403);
});

test("/proxy refuses IPv4-mapped IPv6 loopback (was an SSRF bypass)", async () => {
  const self = `http://[::ffff:127.0.0.1]:${engine.port}/health`;
  const res = await engine.request(`/proxy?url=${enc(self)}&token=${engine.token}`);
  assert.equal(res.status, 502);
  assert.match(res.text, /Blocked destination/);
  assert.doesNotMatch(res.text, /stream proxy OK/);
});

test("/probe requires the session token and rejects unknown keys", async () => {
  const url = enc("https://1.1.1.1/a.mkv");
  assert.equal((await engine.request(`/probe?url=${url}`)).status, 403);
  const extra = await engine.request(`/probe?url=${url}&token=${engine.token}&show_data=1`);
  assert.equal(extra.status, 400);
});

test("/probe refuses loopback upstreams before spawning ffprobe", async () => {
  const res = await engine.request(`/probe?url=${enc("http://[::ffff:127.0.0.1]:1/")}&token=${engine.token}`);
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.text).ok, false);
});

test("/remux rejects malformed start= before spawning FFmpeg", async () => {
  const res = await engine.request(`/remux?url=${enc("https://1.1.1.1/a.mkv")}&start=-5&token=${engine.token}`);
  assert.equal(res.status, 400);
});

test("/engine advertises probe / seek / replace capabilities", async () => {
  const info = JSON.parse((await engine.request("/engine")).text);
  assert.equal(info.remuxReplaces, true);
  assert.equal(info.remuxSeek, true);
  assert.equal(typeof info.probe, "boolean");
  assert.equal(info.probePath, "/probe?url=");
});
