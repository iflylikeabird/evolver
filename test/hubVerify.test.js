const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

describe('hubVerify', function () {
  const { isSolidifyVerifyEnabled, requestSolidifyPermit } = require('../src/gep/hubVerify');

  it('isSolidifyVerifyEnabled returns false when no hub URL', function () {
    const original = process.env.A2A_HUB_URL;
    delete process.env.A2A_HUB_URL;
    assert.strictEqual(isSolidifyVerifyEnabled(), false);
    if (original !== undefined) process.env.A2A_HUB_URL = original;
  });

  it('isSolidifyVerifyEnabled returns false when explicitly disabled', function () {
    const origUrl = process.env.A2A_HUB_URL;
    const origVerify = process.env.EVOLVER_SOLIDIFY_VERIFY;
    const origNodeEnv = process.env.NODE_ENV;
    process.env.A2A_HUB_URL = 'https://example.com';
    process.env.EVOLVER_SOLIDIFY_VERIFY = 'false';
    process.env.NODE_ENV = 'test';
    assert.strictEqual(isSolidifyVerifyEnabled(), false);
    if (origUrl !== undefined) process.env.A2A_HUB_URL = origUrl; else delete process.env.A2A_HUB_URL;
    if (origVerify !== undefined) process.env.EVOLVER_SOLIDIFY_VERIFY = origVerify; else delete process.env.EVOLVER_SOLIDIFY_VERIFY;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv; else delete process.env.NODE_ENV;
  });

  it('isSolidifyVerifyEnabled returns true when hub URL is set', function () {
    const origUrl = process.env.A2A_HUB_URL;
    const origVerify = process.env.EVOLVER_SOLIDIFY_VERIFY;
    process.env.A2A_HUB_URL = 'https://evomap.ai';
    delete process.env.EVOLVER_SOLIDIFY_VERIFY;
    assert.strictEqual(isSolidifyVerifyEnabled(), true);
    if (origUrl !== undefined) process.env.A2A_HUB_URL = origUrl; else delete process.env.A2A_HUB_URL;
    if (origVerify !== undefined) process.env.EVOLVER_SOLIDIFY_VERIFY = origVerify; else delete process.env.EVOLVER_SOLIDIFY_VERIFY;
  });

  it('requestSolidifyPermit returns offline error when no hub URL', async function () {
    const origUrl = process.env.A2A_HUB_URL;
    delete process.env.A2A_HUB_URL;
    try {
      const result = await requestSolidifyPermit({ geneId: 'test_gene', signals: ['a'], mutation: {} });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.offline, true);
    } finally {
      if (origUrl !== undefined) process.env.A2A_HUB_URL = origUrl;
    }
  });

  it('consumeOfflinePermit returns error with offline flag when no token cached', function () {
    const { consumeOfflinePermit } = require('../src/gep/hubVerify');
    const result = consumeOfflinePermit();
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.offline, true);
  });

  it('isSolidifyVerifyEnabled ignores env var disable in non-test env', function () {
    const origUrl = process.env.A2A_HUB_URL;
    const origVerify = process.env.EVOLVER_SOLIDIFY_VERIFY;
    const origNodeEnv = process.env.NODE_ENV;
    process.env.A2A_HUB_URL = 'https://example.com';
    process.env.EVOLVER_SOLIDIFY_VERIFY = 'false';
    process.env.NODE_ENV = 'production';
    assert.strictEqual(isSolidifyVerifyEnabled(), true);
    if (origUrl !== undefined) process.env.A2A_HUB_URL = origUrl; else delete process.env.A2A_HUB_URL;
    if (origVerify !== undefined) process.env.EVOLVER_SOLIDIFY_VERIFY = origVerify; else delete process.env.EVOLVER_SOLIDIFY_VERIFY;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv; else delete process.env.NODE_ENV;
  });
});

describe('hubVerify offline token integrity (C2)', function () {
  // Reset cached module so MEMORY_DIR takes effect on each test
  function freshHubVerify(memDir) {
    process.env.MEMORY_DIR = memDir;
    delete require.cache[require.resolve('../src/gep/hubVerify')];
    return require('../src/gep/hubVerify');
  }

  function makeTokenFile(otPath, token, signingSecret) {
    const data = JSON.stringify(token);
    const hmac = crypto.createHmac('sha256', signingSecret).update(data).digest('hex');
    fs.writeFileSync(otPath, JSON.stringify({ data: token, hmac }), 'utf8');
  }

  function withEnv(overrides, fn) {
    const orig = {};
    for (const k of Object.keys(overrides)) {
      orig[k] = process.env[k];
      if (overrides[k] === undefined) delete process.env[k];
      else process.env[k] = overrides[k];
    }
    try { return fn(); }
    finally {
      for (const k of Object.keys(orig)) {
        if (orig[k] === undefined) delete process.env[k];
        else process.env[k] = orig[k];
      }
      delete require.cache[require.resolve('../src/gep/hubVerify')];
    }
  }

  it('consumeOfflinePermit accepts a token signed with the current nodeSecret', function () {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ot-hmac-'));
    try {
      withEnv({ A2A_NODE_SECRET: 'a'.repeat(64), MEMORY_DIR: tmpDir }, () => {
        const token = { usedCount: 0, expiresAt: Date.now() + 86400000, maxOfflineSolidifies: 10 };
        makeTokenFile(path.join(tmpDir, '.ot'), token, 'a'.repeat(64));
        const hv = freshHubVerify(tmpDir);
        const res = hv.consumeOfflinePermit();
        assert.strictEqual(res.ok, true, 'token with matching HMAC should be accepted');
        assert.strictEqual(res.offline, true);
      });
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    }
  });

  it('rejects token when nodeSecret rotates (clone detection)', function () {
    // A cloned install reuses the .ot file but rotates nodeSecret on first
    // online verify. HMAC verification fails and the token is rejected.
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ot-hmac-'));
    try {
      withEnv({ A2A_NODE_SECRET: 'b'.repeat(64), MEMORY_DIR: tmpDir }, () => {
        const token = { usedCount: 0, expiresAt: Date.now() + 86400000, maxOfflineSolidifies: 10 };
        // Sign with secret A but the running install has secret B.
        makeTokenFile(path.join(tmpDir, '.ot'), token, 'a'.repeat(64));
        const hv = freshHubVerify(tmpDir);
        const res = hv.consumeOfflinePermit();
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.error, 'no_offline_token');
      });
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    }
  });

  it('rejects tampered token data even when HMAC field is present', function () {
    // Attacker forges usedCount=0 to bypass quota, but the HMAC is over the
    // original usedCount=5 payload. Verification fails.
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ot-hmac-'));
    try {
      withEnv({ A2A_NODE_SECRET: 'c'.repeat(64), MEMORY_DIR: tmpDir }, () => {
        const realToken = { usedCount: 5, expiresAt: Date.now() + 86400000, maxOfflineSolidifies: 10 };
        const realHmac = crypto.createHmac('sha256', 'c'.repeat(64)).update(JSON.stringify(realToken)).digest('hex');
        const forgedToken = { usedCount: 0, expiresAt: realToken.expiresAt, maxOfflineSolidifies: 10 };
        fs.writeFileSync(path.join(tmpDir, '.ot'), JSON.stringify({ data: forgedToken, hmac: realHmac }), 'utf8');
        const hv = freshHubVerify(tmpDir);
        const res = hv.consumeOfflinePermit();
        assert.strictEqual(res.ok, false);
        assert.strictEqual(res.error, 'no_offline_token');
      });
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    }
  });
});
