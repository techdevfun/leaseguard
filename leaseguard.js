#!/usr/bin/env node
"use strict";
/*
 * leaseguard — approval leases for agent-run commands.
 *
 * An agent asked you "can I run this?" You said yes at 10:00.
 * It ran the command at 16:00, in a different directory, against
 * different code. Would you still have said yes?
 *
 * leaseguard makes approvals expire by construction:
 *   1. You grant a lease for a specific command pattern, a duration,
 *      and a directory scope:  leaseguard grant "npm run deploy" --for 10m
 *   2. The agent runs commands through the gate:
 *      leaseguard run -L <token> -- npm run deploy
 *   3. The gate checks the lease (signature, expiry, scope, pattern),
 *      a standing allow/deny policy (deny always wins), and logs every
 *      decision to a hash-chained ledger.
 *
 * Honest limit: this stops stale approvals, accidents and casual misuse.
 * It does NOT stop a determined adversary with the same file permissions
 * as you — anyone who can read ~/.leaseguard/key can mint leases.
 * Run it from your CI or your own shell, not from the agent's.
 *
 * Zero dependencies. Node >= 18.
 */

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const HOME_DIR = process.env.LEASEGUARD_HOME || path.join(os.homedir(), ".leaseguard");
const KEY_FILE = path.join(HOME_DIR, "key");
const LEASES_FILE = path.join(HOME_DIR, "leases.json");
const LEDGER_FILE = path.join(HOME_DIR, "ledger.jsonl");
const DEFAULT_LEASE = "15m";

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

function die(code, msg) {
  process.stderr.write(`leaseguard: ${msg}\n`);
  process.exit(code);
}

function ensureHome() {
  fs.mkdirSync(HOME_DIR, { recursive: true });
  try { fs.chmodSync(HOME_DIR, 0o700); } catch (_) { /* non-posix */ }
}

function getKey() {
  ensureHome();
  if (fs.existsSync(KEY_FILE)) return fs.readFileSync(KEY_FILE, "utf8").trim();
  const key = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(KEY_FILE, key + "\n", { mode: 0o600 });
  return key;
}

function parseDuration(str) {
  const m = /^(\d+)(s|m|h|d)$/.exec(String(str || "").trim());
  if (!m) die(1, `bad duration "${str}" — use like 30s, 10m, 2h, 1d`);
  const n = Number(m[1]);
  const mult = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
  return n * mult;
}

function fmtDuration(ms) {
  if (ms % 86_400_000 === 0) return `${ms / 86_400_000}d`;
  if (ms % 3_600_000 === 0) return `${ms / 3_600_000}h`;
  if (ms % 60_000 === 0) return `${ms / 60_000}m`;
  return `${ms / 1000}s`;
}

function globToRegExp(glob) {
  const esc = String(glob).replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp("^" + esc.replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
}

function matchGlob(glob, str) {
  try { return globToRegExp(glob).test(str); }
  catch (_) { return false; }
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  const pad = str + "=".repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(pad.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function sign(payloadJson, key) {
  return crypto.createHmac("sha256", key).update(payloadJson).digest("hex");
}

function mintLeaseToken(lease, key) {
  const payload = b64urlEncode(JSON.stringify(lease));
  return `${payload}.${sign(payload, key)}`;
}

function verifyLeaseToken(token, key) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2) throw new Error("malformed token");
  const [payload, sig] = parts;
  const expected = sign(payload, key);
  const a = Buffer.from(sig, "utf8"), b = Buffer.from(expected, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error("bad signature");
  return JSON.parse(b64urlDecode(payload).toString("utf8"));
}

function withinScope(scope, cwd) {
  const rel = path.relative(path.resolve(scope), path.resolve(cwd));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

// ---------------------------------------------------------------------------
// lease store
// ---------------------------------------------------------------------------

function loadLeases() {
  ensureHome();
  if (!fs.existsSync(LEASES_FILE)) return { leases: [] };
  try { return JSON.parse(fs.readFileSync(LEASES_FILE, "utf8")); }
  catch (_) { return { leases: [] }; }
}

function saveLeases(store) {
  ensureHome();
  fs.writeFileSync(LEASES_FILE, JSON.stringify(store, null, 2) + "\n", { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// hash-chained ledger
// ---------------------------------------------------------------------------

function ledgerAppend(event) {
  ensureHome();
  let prev = "GENESIS", seq = 0;
  if (fs.existsSync(LEDGER_FILE)) {
    const lines = fs.readFileSync(LEDGER_FILE, "utf8").split("\n").filter(Boolean);
    if (lines.length) {
      const last = JSON.parse(lines[lines.length - 1]);
      prev = last.hash; seq = last.seq + 1;
    }
  }
  const entry = { seq, ts: new Date().toISOString(), prev, ...event };
  entry.hash = crypto.createHash("sha256").update(prev + JSON.stringify({ ...entry, hash: undefined })).digest("hex");
  fs.appendFileSync(LEDGER_FILE, JSON.stringify(entry) + "\n");
  return entry;
}

function ledgerVerify() {
  if (!fs.existsSync(LEDGER_FILE)) return { ok: true, count: 0 };
  const lines = fs.readFileSync(LEDGER_FILE, "utf8").split("\n").filter(Boolean);
  let prev = "GENESIS";
  for (let i = 0; i < lines.length; i++) {
    let e;
    try { e = JSON.parse(lines[i]); } catch (_) { return { ok: false, count: lines.length, badAt: i, why: "unparseable line" }; }
    if (e.prev !== prev) return { ok: false, count: lines.length, badAt: i, why: "chain break" };
    const recomputed = crypto.createHash("sha256").update(e.prev + JSON.stringify({ ...e, hash: undefined })).digest("hex");
    if (recomputed !== e.hash) return { ok: false, count: lines.length, badAt: i, why: "hash mismatch" };
    prev = e.hash;
  }
  return { ok: true, count: lines.length };
}

function ledgerRead() {
  if (!fs.existsSync(LEDGER_FILE)) return [];
  return fs.readFileSync(LEDGER_FILE, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
}

// ---------------------------------------------------------------------------
// option parsing (tiny)
// ---------------------------------------------------------------------------

function parseOpts(argv, spec) {
  // spec: { name: "flag" } for booleans; otherwise takes a value
  const opts = {}, rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { rest.push(...argv.slice(i + 1)); break; }
    if (a.startsWith("--")) {
      const name = a.slice(2);
      if (spec[name] === "flag") { opts[name] = true; continue; }
      const val = argv[i + 1];
      if (val === undefined || val.startsWith("--")) die(1, `option --${name} needs a value`);
      opts[name] = val; i++;
    } else if (a.startsWith("-") && a.length === 2) {
      const name = spec[a[1]];
      if (!name) die(1, `unknown option ${a}`);
      if (name === "_flag") { opts[a[1]] = true; continue; }
      const val = argv[i + 1];
      if (val === undefined) die(1, `option ${a} needs a value`);
      opts[name] = val; i++;
    } else rest.push(a);
  }
  return { opts, rest };
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

function cmdGrant(argv) {
  const { opts, rest } = parseOpts(argv, { for: "for", scope: "scope", note: "note", L: null });
  const pattern = rest.join(" ");
  if (!pattern) die(1, 'usage: leaseguard grant "<command pattern>" [--for 10m] [--scope ./dir] [--note "..."]');
  const ms = parseDuration(opts.for || DEFAULT_LEASE);
  const scope = path.resolve(opts.scope || process.cwd());
  const now = Date.now();
  const lease = {
    v: 1,
    id: crypto.randomBytes(6).toString("hex"),
    pattern,
    grantedAt: now,
    expiresAt: now + ms,
    scope,
    note: opts.note || "",
  };
  const key = getKey();
  const store = loadLeases();
  store.leases.push({ ...lease, revoked: false, usedCount: 0, lastUsedAt: null });
  saveLeases(store);
  ledgerAppend({ event: "grant", leaseId: lease.id, pattern, expiresAt: lease.expiresAt, scope, note: lease.note });
  const token = mintLeaseToken(lease, key);
  console.log(`lease ${lease.id} granted`);
  console.log(`  pattern : ${pattern}`);
  console.log(`  valid   : ${fmtDuration(ms)} (until ${new Date(lease.expiresAt).toISOString()})`);
  console.log(`  scope   : ${scope}`);
  if (lease.note) console.log(`  note    : ${lease.note}`);
  console.log(`  token   : ${token}`);
  console.log(`\nrun it with: leaseguard run --lease ${token} -- ${pattern.replace(/\*/g, "<arg>")}`);
}

function loadPolicy(file) {
  let policy;
  try { policy = JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (e) { die(1, `cannot read policy file ${file}: ${e.message}`); }
  if (!Array.isArray(policy.allow)) policy.allow = [];
  if (!Array.isArray(policy.deny)) policy.deny = [];
  return policy;
}

function cmdRun(argv) {
  const dashdash = argv.indexOf("--");
  const optArgv = dashdash === -1 ? argv : argv.slice(0, dashdash);
  const cmdArgv = dashdash === -1 ? [] : argv.slice(dashdash + 1);
  const { opts } = parseOpts(optArgv, { lease: "lease", "lease-file": "lease-file", policy: "policy", L: "lease" });
  if (!cmdArgv.length) die(1, "usage: leaseguard run [--lease TOKEN | --lease-file F] [--policy policy.json] -- <command> [args...]");
  const cmdStr = cmdArgv.join(" ");
  const cwd = process.cwd();

  // 1. standing policy: deny always wins
  let policy = null;
  if (opts.policy) {
    policy = loadPolicy(opts.policy);
    const hit = policy.deny.find(p => matchGlob(p, cmdStr));
    if (hit) {
      ledgerAppend({ event: "deny", reason: "policy-deny", matched: hit, command: cmdStr, cwd });
      die(4, `denied by policy (deny pattern "${hit}")`);
    }
  }

  // 2. policy allow
  let allowedBy = null, leaseRecord = null;
  if (policy) {
    const hit = policy.allow.find(p => matchGlob(p, cmdStr));
    if (hit) allowedBy = `policy allow "${hit}"`;
  }

  // 3. lease check
  if (!allowedBy) {
    let token = opts.lease || process.env.LEASEGUARD_LEASE || null;
    if (opts["lease-file"]) {
      try { token = fs.readFileSync(opts["lease-file"], "utf8").trim(); }
      catch (e) { die(1, `cannot read lease file: ${e.message}`); }
    }
    if (!token) {
      ledgerAppend({ event: "deny", reason: "no-lease", command: cmdStr, cwd });
      die(2, "denied: no lease and no policy allow — grant one first: leaseguard grant \"<pattern>\" --for 10m");
    }
    const key = getKey();
    let lease;
    try { lease = verifyLeaseToken(token, key); }
    catch (e) {
      ledgerAppend({ event: "deny", reason: "lease-invalid", detail: e.message, command: cmdStr, cwd });
      die(3, `denied: lease invalid (${e.message})`);
    }
    if (Date.now() > lease.expiresAt) {
      ledgerAppend({ event: "deny", reason: "lease-expired", leaseId: lease.id, command: cmdStr, cwd });
      die(3, `denied: lease ${lease.id} expired at ${new Date(lease.expiresAt).toISOString()} — ask for a fresh approval`);
    }
    const store = loadLeases();
    const rec = store.leases.find(l => l.id === lease.id);
    if (!rec || rec.revoked) {
      ledgerAppend({ event: "deny", reason: "lease-revoked", leaseId: lease.id, command: cmdStr, cwd });
      die(3, `denied: lease ${lease.id} was revoked`);
    }
    if (!withinScope(lease.scope, cwd)) {
      ledgerAppend({ event: "deny", reason: "lease-scope", leaseId: lease.id, scope: lease.scope, cwd, command: cmdStr });
      die(3, `denied: lease ${lease.id} is scoped to ${lease.scope}, you are in ${cwd}`);
    }
    if (!matchGlob(lease.pattern, cmdStr)) {
      ledgerAppend({ event: "deny", reason: "lease-pattern", leaseId: lease.id, pattern: lease.pattern, command: cmdStr, cwd });
      die(3, `denied: command does not match lease pattern "${lease.pattern}"`);
    }
    allowedBy = `lease ${lease.id}`;
    leaseRecord = rec;
  }

  // 4. execute directly (no shell): argv is passed through untouched, so the
  // exact approved command is what runs. Need pipes? run sh -c explicitly
  // and make the pattern/policy match the full "sh -c ..." string.
  const res = spawnSync(cmdArgv[0], cmdArgv.slice(1), { stdio: "inherit" });
  const exitCode = res.status === null ? 1 : res.status;
  if (leaseRecord) {
    const store = loadLeases();
    const rec = store.leases.find(l => l.id === leaseRecord.id);
    if (rec) { rec.usedCount++; rec.lastUsedAt = Date.now(); saveLeases(store); }
  }
  ledgerAppend({ event: "run", outcome: "allowed", by: allowedBy, command: cmdStr, cwd, exitCode });
  process.exit(exitCode);
}

function cmdLeases() {
  const store = loadLeases();
  const now = Date.now();
  if (!store.leases.length) { console.log("no leases yet — grant one: leaseguard grant \"<pattern>\" --for 10m"); return; }
  for (const l of store.leases) {
    const status = l.revoked ? "revoked"
      : now > l.expiresAt ? "expired"
      : "active";
    console.log(`${l.id}  [${status}]  "${l.pattern}"  scope=${l.scope}  used=${l.usedCount}x  until=${new Date(l.expiresAt).toISOString()}${l.note ? `  note=${l.note}` : ""}`);
  }
}

function cmdRevoke(argv) {
  const id = (argv[0] || "").trim();
  if (!id) die(1, "usage: leaseguard revoke <lease-id>");
  const store = loadLeases();
  const matches = store.leases.filter(l => l.id === id || l.id.startsWith(id));
  if (!matches.length) die(1, `no lease ${id}`);
  if (matches.length > 1) {
    // A short prefix that matches several leases must never silently
    // revoke the first one — the user may have meant any of them.
    const list = matches.map(l => `  ${l.id}  "${l.pattern}"`).join("\n");
    die(1, `ambiguous prefix "${id}" matches ${matches.length} leases — use a longer prefix or the full id:\n${list}`);
  }
  const rec = matches[0];
  rec.revoked = true;
  saveLeases(store);
  ledgerAppend({ event: "revoke", leaseId: rec.id });
  console.log(`lease ${rec.id} revoked`);
}

function cmdAudit(argv) {
  const { opts } = parseOpts(argv, { json: "flag" });
  const store = loadLeases();
  const entries = ledgerRead();
  const chain = ledgerVerify();
  const now = Date.now();
  const active = store.leases.filter(l => !l.revoked && now <= l.expiresAt);
  const expiredUnused = store.leases.filter(l => !l.revoked && now > l.expiresAt && l.usedCount === 0);
  const expiredUsed = store.leases.filter(l => !l.revoked && now > l.expiresAt && l.usedCount > 0);
  const revoked = store.leases.filter(l => l.revoked);
  const allowed = entries.filter(e => e.event === "run" && e.outcome === "allowed");
  const denied = entries.filter(e => e.event === "deny");
  const summary = {
    leases: { total: store.leases.length, active: active.length, revoked: revoked.length, expiredUsed: expiredUsed.length, expiredUnused: expiredUnused.length },
    runs: { allowed: allowed.length, denied: denied.length },
    ledger: { entries: entries.length, chainOk: chain.ok, badAt: chain.badAt ?? null },
  };
  if (opts.json) { console.log(JSON.stringify(summary, null, 2)); return; }
  console.log("leaseguard audit");
  console.log(`  leases : ${summary.leases.total} total — ${active.length} active, ${revoked.length} revoked, ${expiredUsed.length} expired (used), ${expiredUnused.length} expired unused`);
  console.log(`  runs   : ${allowed.length} allowed, ${denied.length} denied`);
  console.log(`  ledger : ${entries.length} entries, hash chain ${chain.ok ? "OK" : `BROKEN at entry ${chain.badAt} (${chain.why})`}`);
  if (expiredUnused.length) {
    console.log("\n  stale approvals that died quietly (expired, never used — nothing ran on your old yes):");
    for (const l of expiredUnused) console.log(`    ${l.id}  "${l.pattern}"  granted ${new Date(l.grantedAt).toISOString()}`);
  }
  if (denied.length) {
    console.log("\n  recent denials:");
    for (const e of denied.slice(-5)) console.log(`    [${e.ts}] ${e.reason}: ${e.command}`);
  }
}

function cmdHelp() {
  console.log(`leaseguard — approval leases for agent-run commands

usage:
  leaseguard grant "<pattern>" [--for 10m] [--scope ./dir] [--note "..."]
      grant a lease: a signed, expiring, directory-scoped approval
      durations like 30s, 10m, 2h, 1d (default 15m)

  leaseguard run [--lease TOKEN | --lease-file F | $LEASEGUARD_LEASE]
                 [--policy policy.json] -- <command> [args...]
      run a command through the gate. deny patterns in the policy
      always win, even over a valid lease. no lease + no policy allow
      = denied. exit codes: 0 ran, 2 denied, 3 bad/expired lease, 4 policy deny

  leaseguard leases            list leases and their status
  leaseguard revoke <id>       revoke a lease immediately
  leaseguard audit [--json]    ledger summary + hash-chain check

policy file (JSON): { "allow": ["npm test", "git status"], "deny": ["rm -rf *"] }

The ledger lives in ~/.leaseguard/ledger.jsonl (override home with
LEASEGUARD_HOME). Every grant, run, denial and revocation is appended
with a hash chain, so tampering is detectable.`);
}

// ---------------------------------------------------------------------------

function main() {
  const [cmd, ...argv] = process.argv.slice(2);
  switch (cmd) {
    case "grant": return cmdGrant(argv);
    case "run": return cmdRun(argv);
    case "leases": return cmdLeases();
    case "revoke": return cmdRevoke(argv);
    case "audit": return cmdAudit(argv);
    case "help": case "--help": case "-h": case undefined: return cmdHelp();
    default: die(1, `unknown command "${cmd}" — try: leaseguard help`);
  }
}

main();
