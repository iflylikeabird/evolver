'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { readSettings, writeSettings, clearSettings, SETTINGS_FILE, SETTINGS_DIR } = require('../src/proxy/server/settings');

describe('settings', () => {
  let tmpDir;

  before(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'settings-test-'));
  });

  after(() => {
    try { fs.rmSync(tmpDir, { recursive: true }); } catch {}
  });

  it('writeSettings creates file and merges data', () => {
    const testFile = path.join(tmpDir, 'settings.json');
    const data = { proxy: { url: 'http://127.0.0.1:19820', pid: 1234 } };
    fs.writeFileSync(testFile, JSON.stringify(data));

    const parsed = JSON.parse(fs.readFileSync(testFile, 'utf8'));
    assert.equal(parsed.proxy.url, 'http://127.0.0.1:19820');
    assert.equal(parsed.proxy.pid, 1234);
  });

  it('readSettings returns empty object for missing file', () => {
    const result = readSettings();
    assert.ok(typeof result === 'object');
  });

  it('writeSettings sets 0o600 on fresh settings file', {
    skip: process.platform === 'win32' ? 'chmod not enforced on Windows' : false,
  }, () => {
    writeSettings({ _test: true });
    const mode = fs.statSync(SETTINGS_FILE).mode & 0o777;
    assert.equal(mode, 0o600, 'settings.json must be owner-read-only after fresh write');
  });

  it('writeSettings tightens 0o644 pre-existing file to 0o600 (upgrade path)', {
    skip: process.platform === 'win32' ? 'chmod not enforced on Windows' : false,
  }, () => {
    // Simulate a pre-existing file with loose permissions (pre-C3 upgrade)
    if (!fs.existsSync(SETTINGS_DIR)) fs.mkdirSync(SETTINGS_DIR, { recursive: true });
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify({}), { encoding: 'utf8', mode: 0o644 });
    fs.chmodSync(SETTINGS_FILE, 0o644);
    assert.equal(fs.statSync(SETTINGS_FILE).mode & 0o777, 0o644, 'precondition: file starts at 0o644');

    writeSettings({ _test: true });
    const mode = fs.statSync(SETTINGS_FILE).mode & 0o777;
    assert.equal(mode, 0o600, 'writeSettings must tighten 0o644 to 0o600');
  });
});
