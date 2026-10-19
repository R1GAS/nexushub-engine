"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const sec = require("../engine-security");

test("tokensEqual compares exactly and rejects empty tokens", () => {
  assert.equal(sec.tokensEqual("abc", "abc"), true);
  assert.equal(sec.tokensEqual("abc", "abd"), false);
  assert.equal(sec.tokensEqual("abc", "abcd"), false);
  assert.equal(sec.tokensEqual("", ""), false);
});

test("readRequestToken reads query, X-NexusHub-Token and Bearer", () => {
  const url = (q) => new URL(`http://127.0.0.1/proxy${q}`);
  assert.equal(sec.readRequestToken({ headers: {} }, url("?token=q")), "q");
  assert.equal(sec.readRequestToken({ headers: { "x-nexushub-token": "h" } }, url("")), "h");
  assert.equal(sec.readRequestToken({ headers: { authorization: "Bearer b " } }, url("")), "b");
  assert.equal(sec.readRequestToken({ headers: {} }, url("")), "");
});

test("isBlockedIp blocks private / loopback / metadata IPv4", () => {
  for (const ip of [
    "0.0.0.0",
    "10.1.2.3",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "224.0.0.1",
    "255.255.255.255",
  ]) {
    assert.equal(sec.isBlockedIp(ip), true, ip);
  }
});

test("isBlockedIp allows public addresses", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111"]) {
    assert.equal(sec.isBlockedIp(ip), false, ip);
  }
});

test("isBlockedIp blocks loopback / ULA / link-local / multicast IPv6", () => {
  for (const ip of ["::", "::1", "fd00::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1"]) {
    assert.equal(sec.isBlockedIp(ip), true, ip);
  }
});

test("assertSafeUpstreamUrl rejects non-http schemes, userinfo, long URLs and private literals", async () => {
  await assert.rejects(sec.assertSafeUpstreamUrl("file:///etc/passwd"), /Only http/);
  await assert.rejects(sec.assertSafeUpstreamUrl("http://user:pw@example.com/"), /userinfo/);
  await assert.rejects(sec.assertSafeUpstreamUrl(`http://example.com/${"a".repeat(9000)}`), /too long/);
  await assert.rejects(sec.assertSafeUpstreamUrl("http://127.0.0.1/"), /Blocked/);
  await assert.rejects(sec.assertSafeUpstreamUrl("http://0x7f000001/"), /Blocked/);
});

test("assertSafeUpstreamUrl accepts public IP literals", async () => {
  const parsed = await sec.assertSafeUpstreamUrl("https://1.1.1.1/stream.ts");
  assert.equal(parsed.hostname, "1.1.1.1");
});

test("createConcurrencyGate caps parallel holders and hands off in order", async () => {
  const gate = sec.createConcurrencyGate(1);
  await gate.acquire();
  let second = false;
  const waiting = gate.acquire().then(() => (second = true));
  await new Promise((r) => setImmediate(r));
  assert.equal(second, false);
  gate.release();
  await waiting;
  assert.equal(second, true);
  assert.equal(gate.active(), 1);
});

test("isBlockedIp blocks IPv4 hidden inside IPv6 (mapped, NAT64, 6to4)", () => {
  for (const ip of [
    "::ffff:7f00:1", // WHATWG URL normalises [::ffff:127.0.0.1] to this
    "::ffff:a9fe:a9fe", // 169.254.169.254
    "::ffff:c0a8:101", // 192.168.1.1
    "0:0:0:0:0:ffff:127.0.0.1",
    "64:ff9b::7f00:1",
    "64:ff9b::10.0.0.1",
    "2002:7f00:1::1",
    "2002:c0a8:0101::",
  ]) {
    assert.equal(sec.isBlockedIp(ip), true, ip);
  }
  assert.equal(sec.isBlockedIp("::ffff:808:808"), false, "mapped public 8.8.8.8");
  assert.equal(sec.isBlockedIp("64:ff9b::808:808"), false, "NAT64 public 8.8.8.8");
});

test("isBlockedIp blocks the full special-purpose IPv6 ranges, not just string prefixes", () => {
  for (const ip of [
    "0:0:0:0:0:0:0:1",
    "::7f00:1", // deprecated IPv4-compatible
    "febf::1", // still fe80::/10
    "fec0::1",
    "2001::1", // Teredo
    "2001:db8::1",
    "100::1",
    "64:ff9b:1::1",
    "fe80::1%en0",
  ]) {
    assert.equal(sec.isBlockedIp(ip), true, ip);
  }
});

test("isBlockedIp blocks benchmarking / TEST-NET IPv4 ranges", () => {
  for (const ip of ["198.18.0.1", "198.19.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1", "240.0.0.1"]) {
    assert.equal(sec.isBlockedIp(ip), true, ip);
  }
});

test("assertSafeUpstreamUrl rejects IPv6-literal loopback / metadata URLs", async () => {
  for (const url of [
    "http://[::ffff:127.0.0.1]:8787/health",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[64:ff9b::127.0.0.1]/",
    "http://[::127.0.0.1]/",
  ]) {
    await assert.rejects(sec.assertSafeUpstreamUrl(url), /Blocked/, url);
  }
});

test("safeLookup refuses hostnames that resolve to blocked addresses", async () => {
  const lookup = (opts) =>
    new Promise((resolve) => sec.safeLookup("localhost", opts, (err, addr) => resolve({ err, addr })));
  const single = await lookup({});
  assert.equal(single.err && single.err.code, "EBLOCKED");
  const all = await lookup({ all: true });
  assert.equal(all.err && all.err.code, "EBLOCKED");
});
