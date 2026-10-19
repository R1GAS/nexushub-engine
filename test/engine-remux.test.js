"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const remux = require("../engine-remux");

const params = (q) => new URLSearchParams(q);

test("parseRemuxQuery rejects unknown keys so FFmpeg flags cannot be smuggled", () => {
  const res = remux.parseRemuxQuery(params("url=https://cdn.example/a.mkv&vf=scale"));
  assert.equal(res.ok, false);
  assert.equal(res.status, 400);
  assert.match(res.error, /Unknown remux parameter: vf/);
});

test("parseRemuxQuery requires url and only allows vcodec=h264", () => {
  assert.equal(remux.parseRemuxQuery(params("")).status, 400);
  assert.equal(remux.parseRemuxQuery(params("url=https://x/a.mkv&vcodec=hevc")).status, 400);
  const ok = remux.parseRemuxQuery(params("url=https://x/a.mkv&vcodec=h264&token=t"));
  assert.equal(ok.ok, true);
  assert.equal(ok.transcodeVideo, true);
  assert.equal(remux.parseRemuxQuery(params("url=https://x/a.mkv&transcode=1")).transcodeVideo, true);
  assert.equal(remux.parseRemuxQuery(params("url=https://x/a.mkv")).transcodeVideo, false);
});

test("buildFfmpegArgs uses fixed templates with the URL as the only -i input", () => {
  const url = "https://cdn.example/a.mkv?sig=1";
  const copy = remux.buildFfmpegArgs(url);
  assert.equal(copy[copy.indexOf("-i") + 1], url);
  assert.equal(copy.filter((a) => a === "-i").length, 1);
  assert.deepEqual(copy.slice(copy.indexOf("-c:v"), copy.indexOf("-c:v") + 2), ["-c:v", "copy"]);
  assert.equal(copy[copy.length - 1], "pipe:1");

  const tx = remux.buildFfmpegArgs(url, { transcodeVideo: true });
  assert.equal(tx[tx.indexOf("-c:v") + 1], "libx264");
});

test("sanitizeFfmpegBinary only accepts an existing file named ffmpeg", () => {
  assert.equal(remux.sanitizeFfmpegBinary(""), "");
  assert.equal(remux.sanitizeFfmpegBinary("/bin/sh"), "");
  assert.equal(remux.sanitizeFfmpegBinary("/nonexistent/ffmpeg"), "");
  assert.equal(remux.sanitizeFfmpegBinary("ffmpeg\n--evil"), "");
});

test("buildFfmpegArgs pins FFmpeg input protocols to network-only", () => {
  const args = remux.buildFfmpegArgs("https://cdn.example/a.m3u8");
  const i = args.indexOf("-protocol_whitelist");
  assert.ok(i !== -1 && i < args.indexOf("-i"));
  assert.equal(args[i + 1], "http,https,tcp,tls,crypto");
});

test("parseRemuxQuery accepts start= as plain decimal seconds only", () => {
  assert.equal(remux.parseRemuxQuery(params("url=https://x/a.mkv")).startSeconds, 0);
  assert.equal(remux.parseRemuxQuery(params("url=https://x/a.mkv&start=754.25")).startSeconds, 754.25);
  for (const bad of ["-1", "1e3", "abc", "0x10", "12.3456", "86401", " 5", "5;", "NaN", "Infinity"]) {
    const res = remux.parseRemuxQuery(params(`url=https://x/a.mkv&start=${encodeURIComponent(bad)}`));
    assert.equal(res.ok, false, bad);
    assert.equal(res.status, 400, bad);
  }
});

test("buildFfmpegArgs input-seeks with a normalised -ss before -i", () => {
  const args = remux.buildFfmpegArgs("https://cdn.example/a.mkv", { startSeconds: 90.5 });
  const ss = args.indexOf("-ss");
  assert.ok(ss !== -1 && ss < args.indexOf("-i"));
  assert.equal(args[ss + 1], "90.500");
  assert.equal(remux.buildFfmpegArgs("https://cdn.example/a.mkv", { startSeconds: 0 }).includes("-ss"), false);
});

test("parseProbeQuery only allows url + token", () => {
  assert.equal(remux.parseProbeQuery(params("url=https://x/a.mkv&token=t")).ok, true);
  assert.equal(remux.parseProbeQuery(params("")).status, 400);
  const smuggle = remux.parseProbeQuery(params("url=https://x/a.mkv&show_data=1"));
  assert.equal(smuggle.status, 400);
  assert.match(smuggle.error, /Unknown probe parameter/);
});

test("buildFfprobeArgs is a fixed JSON template with the URL as the only -i input", () => {
  const url = "https://cdn.example/a.mkv?sig=1";
  const args = remux.buildFfprobeArgs(url);
  assert.equal(args[args.indexOf("-i") + 1], url);
  assert.equal(args[args.length - 1], url);
  assert.equal(args[args.indexOf("-of") + 1], "json");
  assert.equal(args[args.indexOf("-protocol_whitelist") + 1], "http,https,tcp,tls,crypto");
});

test("summarizeProbe reduces ffprobe JSON to container, duration and per-type streams", () => {
  const info = remux.summarizeProbe({
    format: { format_name: "matroska,webm", duration: "5400.123000", bit_rate: "8000000" },
    streams: [
      { index: 0, codec_type: "video", codec_name: "hevc", profile: "Main 10", width: 3840, height: 2160, pix_fmt: "yuv420p10le" },
      { index: 1, codec_type: "audio", codec_name: "eac3", channels: 6, channel_layout: "5.1(side)", sample_rate: "48000", tags: { language: "eng", title: "DD+ 5.1" } },
      { index: 2, codec_type: "subtitle", codec_name: "subrip", tags: { language: "eng" } },
      { index: 3, codec_type: "attachment", codec_name: "ttf" },
    ],
  });
  assert.equal(info.container, "matroska,webm");
  assert.equal(info.duration, 5400.123);
  assert.equal(info.bitRate, 8000000);
  assert.deepEqual(info.video, [
    { index: 0, codec: "hevc", profile: "Main 10", width: 3840, height: 2160, pixFmt: "yuv420p10le" },
  ]);
  assert.equal(info.audio[0].codec, "eac3");
  assert.equal(info.audio[0].channels, 6);
  assert.equal(info.audio[0].sampleRate, 48000);
  assert.equal(info.audio[0].language, "eng");
  assert.equal(info.subtitles.length, 1);
});

test("summarizeProbe tolerates live streams with no duration", () => {
  const info = remux.summarizeProbe({ format: { format_name: "mpegts", duration: "N/A" }, streams: [] });
  assert.equal(info.duration, null);
  assert.deepEqual(info.video, []);
});
