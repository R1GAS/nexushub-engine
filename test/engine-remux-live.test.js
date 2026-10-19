"use strict";

/**
 * Live FFmpeg tests — opt-in because they need FFmpeg and a public media URL:
 *   NEXUSHUB_TEST_MEDIA_URL=https://…/clip.mkv npm test
 * The SSRF filter (correctly) refuses a loopback fixture server, so these cannot run offline.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const remux = require("../engine-remux");
const { startEngine } = require("./helpers");

const MEDIA = process.env.NEXUSHUB_TEST_MEDIA_URL || "";
const skip = !MEDIA ? "set NEXUSHUB_TEST_MEDIA_URL to run" : !remux.isFfmpegAvailable() ? "ffmpeg not found" : false;

/** Resolve once response headers arrive; the body keeps streaming on `res`. */
function openStream(port, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: pathname }, (res) => resolve({ req, res }));
    req.on("error", reject);
  });
}

function readFirstBytes(res, n) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (c) => {
      buf = Buffer.concat([buf, c]);
      if (buf.length >= n) {
        res.off("data", onData);
        resolve(buf);
      }
    };
    res.on("data", onData);
    res.once("end", () => resolve(buf));
    res.once("error", reject);
  });
}

let engine;
test.before(async () => {
  if (!skip) engine = await startEngine();
});
test.after(async () => {
  if (engine) await engine.stop();
});

const remuxPath = (extra = "") =>
  `/remux?url=${encodeURIComponent(MEDIA)}&token=${engine.token}${extra}`;

test("/remux streams fragmented MP4", { skip }, async () => {
  const { req, res } = await openStream(engine.port, remuxPath());
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers["content-type"], "video/mp4");
  const head = await readFirstBytes(res, 16);
  assert.equal(head.subarray(4, 8).toString("latin1"), "ftyp");
  req.destroy();
});

test("a second /remux replaces the running one instead of 429", { skip }, async () => {
  const first = await openStream(engine.port, remuxPath());
  assert.equal(first.res.statusCode, 200);
  const firstEnded = new Promise((resolve) => first.res.once("close", resolve));
  first.res.resume();

  const second = await openStream(engine.port, remuxPath());
  assert.equal(second.res.statusCode, 200);
  await firstEnded;

  const activity = JSON.parse((await engine.request(`/activity?token=${engine.token}`)).text);
  assert.equal(activity.remuxBusy, true);
  assert.equal(activity.active.filter((a) => a.kind === "remux").length, 1);

  const head = await readFirstBytes(second.res, 16);
  assert.equal(head.subarray(4, 8).toString("latin1"), "ftyp");
  second.req.destroy();
});

function readAll(res) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c));
    res.once("end", () => resolve(Buffer.concat(chunks)));
    res.once("error", reject);
  });
}

function durationOf(buf) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "nexushub-test-")), "out.mp4");
  fs.writeFileSync(file, buf);
  const out = spawnSync(remux.resolveFfprobePath(), ["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", file], {
    encoding: "utf8",
  });
  fs.rmSync(path.dirname(file), { recursive: true, force: true });
  return Number(out.stdout.trim());
}

test("/probe summarises the upstream", { skip: skip || (!remux.isFfprobeAvailable() && "ffprobe not found") }, async () => {
  const res = await engine.request(`/probe?url=${encodeURIComponent(MEDIA)}&token=${engine.token}`);
  assert.equal(res.status, 200, res.text);
  const info = JSON.parse(res.text);
  assert.equal(info.ok, true);
  assert.ok(info.container);
  assert.ok(info.duration > 0);
  assert.ok(info.video.length >= 1);
});

test("/remux start= seeks into the upstream", { skip: skip || (!remux.isFfprobeAvailable() && "ffprobe not found") }, async () => {
  const probe = JSON.parse((await engine.request(`/probe?url=${encodeURIComponent(MEDIA)}&token=${engine.token}`)).text);
  const start = Math.floor(probe.duration / 2);
  // Transcode so the cut is frame-exact; copy mode starts at the keyframe at/before start.
  const { res } = await openStream(engine.port, remuxPath(`&start=${start}&transcode=1`));
  assert.equal(res.statusCode, 200);
  const remaining = durationOf(await readAll(res));
  const expected = probe.duration - start;
  assert.ok(Math.abs(remaining - expected) < 0.5, `remaining ${remaining}s, expected ~${expected}s after start=${start}`);
});
