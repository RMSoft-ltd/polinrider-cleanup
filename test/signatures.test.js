import { test, after } from "node:test";
import assert from "node:assert/strict";
import {
  decodeUnicodeEscapes,
  hasHeavyUnicodeEscapeDensity,
  isDetachedSpawn,
  hasEthRpcMethodLiteral,
} from "../src/signatures.js";
import { cleanupAll, LEGIT_I18N_MODULE, FUTURE_VARIANT_PAYLOAD, GENERIC_PAYLOAD } from "./helpers.js";

after(cleanupAll);

test("decodeUnicodeEscapes: plain text passes through; \\uXXXX sequences decode to characters", () => {
  assert.equal(decodeUnicodeEscapes("plain text"), "plain text");
  assert.equal(decodeUnicodeEscapes("\\u0068\\u0069"), "hi");
});

test("hasHeavyUnicodeEscapeDensity: false on empty/non-string/sparse legit i18n text, true on inlined-escape payload", () => {
  assert.equal(hasHeavyUnicodeEscapeDensity(""), false);
  assert.equal(hasHeavyUnicodeEscapeDensity(undefined), false);
  assert.equal(hasHeavyUnicodeEscapeDensity(LEGIT_I18N_MODULE), false);
  assert.equal(hasHeavyUnicodeEscapeDensity(FUTURE_VARIANT_PAYLOAD), true);
});

test("isDetachedSpawn: requires spawn + detached(true|!0) + .unref() together; matches minified !0 boolean", () => {
  assert.equal(isDetachedSpawn(`spawn("node",[])`), false);
  assert.equal(isDetachedSpawn(`spawn("node",[],{detached:true})`), false); // no .unref()
  assert.equal(isDetachedSpawn(`const c=spawn("node",["-e","1"],{detached:!0});c.unref();`), true);
  assert.equal(isDetachedSpawn(`const c=spawn("node",["-e","1"],{detached:true});c.unref();`), true);
});

test("hasEthRpcMethodLiteral: matches known EtherHiding RPC method names only", () => {
  assert.equal(hasEthRpcMethodLiteral(`fetch("/api/eth_call")`), false);
  assert.equal(hasEthRpcMethodLiteral(`method:"eth_getBlockByNumber"`), true);
  assert.equal(hasEthRpcMethodLiteral(`method:"eth_getTransactionCount"`), true);
  assert.equal(hasEthRpcMethodLiteral(`method:"eth_blockNumber"`), true);
});

test("decode-before-match matters: escaped RPC method name only matches after decoding", () => {
  const escaped =
    '"' +
    "eth_getBlockByNumber"
      .split("")
      .map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)
      .join("") +
    '"';
  assert.equal(hasEthRpcMethodLiteral(escaped), false, "raw escaped text should not match directly");
  assert.equal(hasEthRpcMethodLiteral(decodeUnicodeEscapes(escaped)), true, "decoded text should match");
});

test("GENERIC_PAYLOAD (bracket+decoder-array variant) does not trip the new EtherHiding-specific signals", () => {
  assert.equal(hasEthRpcMethodLiteral(GENERIC_PAYLOAD), false);
  assert.equal(isDetachedSpawn(GENERIC_PAYLOAD), false);
});
