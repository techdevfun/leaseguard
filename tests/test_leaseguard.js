const { test, describe, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const BIN = path.join(__dirname, "..", "leaseguard.js");
let HOME;

function run(args, opts = {}) {
  // returns { status, stdout, stderr } without throwing
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    env: { ...process.env, LEASEGUARD_HOME: HOME },
    cwd: opts.cwd || HOME,
  });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

function grant(pattern, extra = []) {
  const r = run(["grant", pattern, ...extra]);
  assert.equal(r.status, 0, `grant failed: ${r.stderr}`);
  const tokenLine = r.stdout.split("\n").find(l => l.includes("token   :"));
  const token = tokenLine.split(":")[1].trim();
  const idLine = r.stdout.split("\n")[0];
  const id = idLine.split(" ")[1];
  return { token, id, out: r.stdout };
}

beforeEach(() => {
  HOME = fs.mkdtempSync(path.join(os.tmpdir(), "lg-test-"));
});

describe("grant", () => {
  test("grants a lease and prints a token", () => {
    const { token, out } = grant("npm run deploy", ["--for", "10m", "--note", "hotfix"]);
    assert.ok(token.includes("."), "token has payload.signature shape");
    assert.ok(out.includes("10m"));
    assert.ok(out.includes("hotfix"));
  });

  test("rejects missing pattern", () => {
    const r = run(["grant"]);
    assert.equal(r.status, 1);
  });

  test("rejects bad duration", () => {
    const r = run(["grant", "x", "--for", "ten minutes"]);
    assert.equal(r.status, 1);
  });
});

describe("run with lease", () => {
  test("runs a matching command and exits with its code", () => {
    const { token } = grant("echo hello-*", ["--for", "10m"]);
    const r = run(["run", "--lease", token, "--", "echo", "hello-world"], { cwd: HOME });
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes("hello-world"));
  });

  test("propagates the command exit code", () => {
    const { token } = grant("node -e *", ["--for", "10m"]);
    const r = run(["run", "--lease", token, "--", "node", "-e", "process.exit(7)"], { cwd: HOME });
    assert.equal(r.status, 7);
  });

  test("denies a command that does not match the pattern", () => {
    const { token } = grant("npm test", ["--for", "10m"]);
    const r = run(["run", "--lease", token, "--", "rm", "-rf", "dist"], { cwd: HOME });
    assert.equal(r.status, 3);
    assert.ok(r.stderr.includes("does not match"));
  });

  test("denies after expiry", () => {
    const { token } = grant("echo *", ["--for", "1s"]);
    const ok = run(["run", "--lease", token, "--", "echo", "fresh"], { cwd: HOME });
    assert.equal(ok.status, 0);
    // wait out the lease
    const start = Date.now();
    while (Date.now() - start < 1200) { /* busy wait, deterministic in CI */ }
    const r = run(["run", "--lease", token, "--", "echo", "stale"], { cwd: HOME });
    assert.equal(r.status, 3);
    assert.ok(r.stderr.includes("expired"));
  });

  test("denies outside the granted scope", () => {
    const sub = path.join(HOME, "proj");
    fs.mkdirSync(sub);
    const { token } = grant("echo *", ["--for", "10m", "--scope", sub]);
    const r = run(["run", "--lease", token, "--", "echo", "x"], { cwd: HOME });
    assert.equal(r.status, 3);
    assert.ok(r.stderr.includes("scoped to"));
  });

  test("denies a tampered token", () => {
    const { token } = grant("echo *", ["--for", "10m"]);
    const tampered = token.slice(0, -2) + "ff";
    const r = run(["run", "--lease", tampered, "--", "echo", "x"], { cwd: HOME });
    assert.equal(r.status, 3);
    assert.ok(r.stderr.includes("invalid"));
  });

  test("revoked lease is denied", () => {
    const { token, id } = grant("echo *", ["--for", "10m"]);
    const rev = run(["revoke", id]);
    assert.equal(rev.status, 0);
    const r = run(["run", "--lease", token, "--", "echo", "x"], { cwd: HOME });
    assert.equal(r.status, 3);
    assert.ok(r.stderr.includes("revoked"));
  });

  test("reads lease from env var", () => {
    const { token } = grant("echo *", ["--for", "10m"]);
    const r = spawnSync(process.execPath, [BIN, "run", "--", "echo", "env-ok"], {
      encoding: "utf8",
      env: { ...process.env, LEASEGUARD_HOME: HOME, LEASEGUARD_LEASE: token },
      cwd: HOME,
    });
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes("env-ok"));
  });
});

describe("policy", () => {
  function writePolicy(p) {
    const f = path.join(HOME, "policy.json");
    fs.writeFileSync(f, JSON.stringify(p));
    return f;
  }

  test("allow pattern runs without a lease", () => {
    const f = writePolicy({ allow: ["npm test"], deny: [] });
    const r = run(["run", "--policy", f, "--", "npm", "test"], { cwd: HOME });
    assert.notEqual(r.status, 2, r.stderr); // may fail if npm missing, but not "denied"
  });

  test("deny wins over a valid lease", () => {
    const f = writePolicy({ allow: [], deny: ["rm -rf *"] });
    const { token } = grant("rm -rf *", ["--for", "10m"]);
    const r = run(["run", "--policy", f, "--lease", token, "--", "rm", "-rf", "dist"], { cwd: HOME });
    assert.equal(r.status, 4);
    assert.ok(r.stderr.includes("denied by policy"));
  });

  test("no lease and no matching allow is denied", () => {
    const f = writePolicy({ allow: ["npm test"], deny: [] });
    const r = run(["run", "--policy", f, "--", "rm", "-rf", "dist"], { cwd: HOME });
    assert.equal(r.status, 2);
  });
});

describe("ledger and audit", () => {
  test("ledger hash chain verifies and audit counts", () => {
    const { token } = grant("echo *", ["--for", "10m"]);
    run(["run", "--lease", token, "--", "echo", "a"], { cwd: HOME });
    run(["run", "--", "echo", "denied-no-lease"], { cwd: HOME }); // denied
    const r = run(["audit", "--json"]);
    assert.equal(r.status, 0);
    const s = JSON.parse(r.stdout);
    assert.equal(s.ledger.chainOk, true);
    assert.ok(s.ledger.entries >= 3);
    assert.equal(s.runs.allowed, 1);
    assert.equal(s.runs.denied, 1);
  });

  test("audit flags expired-unused leases as stale approvals", () => {
    grant("echo *", ["--for", "1s", "--note", "never used"]);
    const start = Date.now();
    while (Date.now() - start < 1200) { /* busy wait */ }
    const r = run(["audit"]);
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes("stale approvals"));
    assert.ok(r.stdout.includes("expired unused"));
  });

  test("tampering with the ledger is detected", () => {
    grant("echo *", ["--for", "10m"]);
    const ledger = path.join(HOME, "ledger.jsonl");
    fs.appendFileSync(ledger, fs.readFileSync(ledger, "utf8").split("\n").filter(Boolean)[0] + "\n"); // duplicate line breaks chain
    const r = run(["audit"]);
    assert.ok(r.stdout.includes("BROKEN"));
  });
});

describe("leases listing", () => {
  test("lists granted leases with status", () => {
    const { id } = grant("echo *", ["--for", "10m"]);
    const r = run(["leases"]);
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes(id));
    assert.ok(r.stdout.includes("active"));
  });
});

describe("revoke", () => {
  test("refuses an ambiguous prefix instead of revoking the first match", () => {
    // Craft two leases sharing a prefix: random ids rarely collide, so
    // seed the store directly rather than hoping for a collision.
    const store = {
      leases: [
        { id: "ab1111111111", pattern: "npm test", grantedAt: 1, expiresAt: 9999999999999, scope: HOME, note: "", revoked: false, usedCount: 0, lastUsedAt: null },
        { id: "ab2222222222", pattern: "rm -rf dist", grantedAt: 1, expiresAt: 9999999999999, scope: HOME, note: "", revoked: false, usedCount: 0, lastUsedAt: null },
      ],
    };
    fs.writeFileSync(path.join(HOME, "leases.json"), JSON.stringify(store));
    const r = run(["revoke", "ab"]);
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes("ambiguous"));
    assert.ok(r.stderr.includes("ab1111111111"));
    assert.ok(r.stderr.includes("ab2222222222"));
    const after = JSON.parse(fs.readFileSync(path.join(HOME, "leases.json"), "utf8"));
    assert.ok(after.leases.every(l => !l.revoked), "no lease may be revoked on an ambiguous prefix");
    // A longer, unambiguous prefix still works.
    const ok = run(["revoke", "ab1"]);
    assert.equal(ok.status, 0);
    assert.ok(ok.stdout.includes("ab1111111111"));
  });
});
