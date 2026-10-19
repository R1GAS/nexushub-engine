"use strict";

/**
 * Shared Engine proxy hardening (Phase 1):
 * session token helpers, SSRF / destination checks, size limits, safe logging.
 */
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const { URL } = require("url");

const MAX_URL_LENGTH = Number(process.env.NEXUSHUB_MAX_URL_LENGTH || 8192);
const MAX_REDIRECTS = Number(process.env.NEXUSHUB_MAX_REDIRECTS || 5);
const MAX_BUFFER_BYTES = Number(process.env.NEXUSHUB_MAX_BUFFER_BYTES || 32 * 1024 * 1024);
const MAX_CONCURRENT_UPSTREAM = Number(process.env.NEXUSHUB_MAX_CONCURRENT || 8);

function generateSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function tokensEqual(a, b) {
  const left = Buffer.from(String(a || ""), "utf8");
  const right = Buffer.from(String(b || ""), "utf8");
  if (left.length !== right.length || left.length === 0) return false;
  return crypto.timingSafeEqual(left, right);
}

/** Extract session token from query, Authorization Bearer, or X-NexusHub-Token. */
function readRequestToken(req, reqUrl) {
  const q = reqUrl && reqUrl.searchParams ? reqUrl.searchParams.get("token") : "";
  if (q) return String(q);
  const header = req && req.headers ? req.headers["x-nexushub-token"] : "";
  if (header) return String(header);
  const auth = req && req.headers ? String(req.headers.authorization || "") : "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m ? m[1].trim() : "";
}

/** IANA special-purpose IPv4 ranges that must never be an upstream ([a, b, c, d], prefix). */
const BLOCKED_V4 = [
  [[0, 0, 0, 0], 8], // "this" network
  [[10, 0, 0, 0], 8],
  [[100, 64, 0, 0], 10], // CGNAT
  [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16], // link-local / cloud metadata
  [[172, 16, 0, 0], 12],
  [[192, 0, 0, 0], 24], // IETF protocol assignments
  [[192, 0, 2, 0], 24], // TEST-NET-1
  [[192, 88, 99, 0], 24], // 6to4 relay anycast
  [[192, 168, 0, 0], 16],
  [[198, 18, 0, 0], 15], // benchmarking
  [[198, 51, 100, 0], 24], // TEST-NET-2
  [[203, 0, 113, 0], 24], // TEST-NET-3
  [[224, 0, 0, 0], 3], // multicast + reserved + broadcast (224/4, 240/4)
];

/** IPv6 ranges blocked outright ([16-bit groups], prefix). */
const BLOCKED_V6 = [
  [[0, 0, 0, 0, 0, 0], 96], // ::, ::1 and deprecated IPv4-compatible
  [[0x0064, 0xff9b, 0x0001], 48], // local-use NAT64
  [[0x0100, 0, 0, 0], 64], // discard-only
  [[0x2001, 0x0000], 32], // Teredo (embedded client address is obfuscated)
  [[0x2001, 0x0db8], 32], // documentation
  [[0xfc00], 7], // ULA
  [[0xfe80], 10], // link-local
  [[0xfec0], 10], // deprecated site-local
  [[0xff00], 8], // multicast
];

function prefixMatches(bytes, prefixBytes, bits) {
  for (let i = 0; i < bits; i += 1) {
    const byte = i >> 3;
    const mask = 0x80 >> (i & 7);
    if ((bytes[byte] & mask) !== ((prefixBytes[byte] || 0) & mask)) return false;
  }
  return true;
}

function parseIPv4(raw) {
  if (net.isIP(raw) !== 4) return null;
  return raw.split(".").map((n) => Number(n));
}

/** Expand any valid IPv6 literal (incl. "::" and dotted-quad tails) to 16 bytes. */
function parseIPv6(raw) {
  const addr = raw.replace(/%.*$/, ""); // zone id
  if (net.isIP(addr) !== 6) return null;
  let head = addr;
  const tail = [];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(addr);
  if (dotted) {
    const v4 = parseIPv4(dotted[1]);
    if (!v4) return null;
    tail.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
    head = addr.slice(0, -dotted[1].length);
    if (!head.endsWith("::")) head = head.replace(/:$/, "");
  }
  const halves = head.split("::");
  const toGroups = (s) => (s ? s.split(":").filter(Boolean).map((g) => parseInt(g, 16)) : []);
  const left = toGroups(halves[0]);
  const right = toGroups(halves[1]).concat(tail);
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (missing < 0) return null;
  return groupsToBytes(left.concat(new Array(missing).fill(0), right));
}

function groupsToBytes(groups) {
  const bytes = [];
  for (const g of groups) bytes.push((g >> 8) & 0xff, g & 0xff);
  return bytes;
}

function isBlockedV4Bytes(v4) {
  return BLOCKED_V4.some(([prefix, bits]) => prefixMatches(v4, prefix, bits));
}

/**
 * IPv4 address carried inside an IPv6 address (mapped, NAT64, 6to4).
 * These all reach the embedded IPv4 host, so they must be checked against BLOCKED_V4.
 */
function embeddedIPv4(bytes) {
  const zero = (from, to) => bytes.slice(from, to).every((b) => b === 0);
  if (zero(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) return bytes.slice(12); // ::ffff:0:0/96
  if (prefixMatches(bytes, groupsToBytes([0x0064, 0xff9b, 0, 0, 0, 0]), 96)) return bytes.slice(12); // NAT64
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return bytes.slice(2, 6); // 6to4
  return null;
}

function isBlockedIp(ip) {
  const raw = String(ip || "").trim().toLowerCase();
  if (!raw) return true;

  const v4 = parseIPv4(raw);
  if (v4) return isBlockedV4Bytes(v4);

  const v6 = parseIPv6(raw);
  if (v6) {
    const inner = embeddedIPv4(v6);
    if (inner) return isBlockedV4Bytes(inner);
    return BLOCKED_V6.some(([groups, bits]) => prefixMatches(v6, groupsToBytes(groups), bits));
  }

  return true;
}

function safeLogHost(rawUrl) {
  try {
    const u = new URL(String(rawUrl || ""));
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return "(invalid-url)";
  }
}

/**
 * Allow only http(s). Resolve hostname and reject private / loopback / metadata IPs.
 * Call again on every redirect hop.
 */
async function assertSafeUpstreamUrl(rawUrl) {
  if (String(rawUrl || "").length > MAX_URL_LENGTH) {
    throw new Error("URL too long");
  }
  let parsed;
  try {
    parsed = new URL(String(rawUrl || ""));
  } catch {
    throw new Error("Invalid URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http(s) upstream URLs are allowed");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URL userinfo not allowed");
  }

  const hostname = String(parsed.hostname || "").replace(/^\[|\]$/g, "");
  if (!hostname) throw new Error("Missing host");

  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) throw new Error("Blocked destination address");
    return parsed;
  }

  let records;
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error("DNS lookup failed");
  }
  if (!records || !records.length) throw new Error("DNS lookup returned no addresses");
  for (const row of records) {
    if (isBlockedIp(row.address)) {
      throw new Error("Blocked destination address (DNS)");
    }
  }
  return parsed;
}

/**
 * `lookup` for http(s).request: re-validates the addresses the socket actually connects to,
 * so a hostname cannot pass assertSafeUpstreamUrl and then rebind to a private address.
 */
function safeLookup(hostname, options, callback) {
  const opts = typeof options === "function" ? {} : { ...(options || {}) };
  const cb = typeof options === "function" ? options : callback;
  dns.lookup(hostname, { ...opts, all: true, verbatim: true }).then(
    (records) => {
      if (!records || !records.length) {
        cb(Object.assign(new Error("DNS lookup returned no addresses"), { code: "ENOTFOUND" }));
        return;
      }
      if (records.some((row) => isBlockedIp(row.address))) {
        cb(Object.assign(new Error("Blocked destination address (DNS)"), { code: "EBLOCKED" }));
        return;
      }
      if (opts.all) cb(null, records);
      else cb(null, records[0].address, records[0].family);
    },
    (error) => cb(error)
  );
}

function createConcurrencyGate(limit = MAX_CONCURRENT_UPSTREAM) {
  let active = 0;
  const waiters = [];
  const acquire = () =>
    new Promise((resolve) => {
      if (active < limit) {
        active += 1;
        resolve();
        return;
      }
      waiters.push(resolve);
    });
  const release = () => {
    active = Math.max(0, active - 1);
    const next = waiters.shift();
    if (next) {
      active += 1;
      next();
    }
  };
  return { acquire, release, active: () => active };
}

module.exports = {
  MAX_URL_LENGTH,
  MAX_REDIRECTS,
  MAX_BUFFER_BYTES,
  MAX_CONCURRENT_UPSTREAM,
  generateSessionToken,
  tokensEqual,
  readRequestToken,
  isBlockedIp,
  safeLookup,
  safeLogHost,
  assertSafeUpstreamUrl,
  createConcurrencyGate,
};
