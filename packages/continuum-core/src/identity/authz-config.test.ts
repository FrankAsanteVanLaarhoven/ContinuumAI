/** S4B — configuration guards: provider-neutral, fail-closed. */
import { describe, expect, it } from "vitest";
import {
  assertBoundedTransactionTtl,
  assertProductionAuthzConfig,
  assertS256,
  resolveAuthCodeFlowMode,
  resolveAuthTransactionStoreMode,
  resolveCodeExchangerMode,
  resolvePkceSecretStoreMode,
} from "./index";

describe("S4B config guards", () => {
  it("deterministic flow / fixture exchanger / test-protected PKCE are dev-only", () => {
    expect(resolveAuthCodeFlowMode({ NODE_ENV: "development", CONTINUUM_AUTH_CODE_FLOW: "deterministic" })).toBe("deterministic");
    expect(() => resolveAuthCodeFlowMode({ NODE_ENV: "production", CONTINUUM_AUTH_CODE_FLOW: "deterministic" })).toThrow(/refused in production/i);
    expect(resolveCodeExchangerMode({ NODE_ENV: "test", CONTINUUM_CODE_EXCHANGER: "fixture" })).toBe("fixture");
    expect(() => resolveCodeExchangerMode({ NODE_ENV: "production", CONTINUUM_CODE_EXCHANGER: "fixture" })).toThrow(/refused in production/i);
    expect(resolvePkceSecretStoreMode({ NODE_ENV: "test", CONTINUUM_PKCE_SECRET_STORE: "test-protected" })).toBe("test-protected");
    expect(() => resolvePkceSecretStoreMode({ NODE_ENV: "production", CONTINUUM_PKCE_SECRET_STORE: "test-protected" })).toThrow(/refused in production/i);
  });

  it("transaction store requires postgres in production; no memory fallback", () => {
    expect(resolveAuthTransactionStoreMode({ CONTINUUM_AUTH_TRANSACTION_STORE: "postgres" })).toBe("postgres");
    expect(resolveAuthTransactionStoreMode({ NODE_ENV: "development", CONTINUUM_AUTH_TRANSACTION_STORE: "memory" })).toBe("memory");
    expect(() => resolveAuthTransactionStoreMode({ NODE_ENV: "production", CONTINUUM_AUTH_TRANSACTION_STORE: "memory" })).toThrow(/refused in production/i);
    expect(() => resolveAuthTransactionStoreMode({ NODE_ENV: "production" })).toThrow(/postgres/i);
  });

  it("plain PKCE is unsupported and lifetimes must be bounded", () => {
    expect(() => assertS256("S256")).not.toThrow();
    expect(() => assertS256("plain")).toThrow(/only S256/i);
    expect(() => assertBoundedTransactionTtl(300)).not.toThrow();
    for (const bad of [0, -1, Number.POSITIVE_INFINITY, 100000]) {
      expect(() => assertBoundedTransactionTtl(bad)).toThrow(/bounded positive/i);
    }
  });

  it("production startup guard fails closed while only test implementations exist", () => {
    expect(() => assertProductionAuthzConfig({ NODE_ENV: "development" })).not.toThrow();
    expect(() =>
      assertProductionAuthzConfig({
        NODE_ENV: "production", CONTINUUM_AUTH_CODE_FLOW: "deterministic", CONTINUUM_AUTH_TRANSACTION_STORE: "postgres",
        CONTINUUM_CODE_EXCHANGER: "fixture", CONTINUUM_PKCE_SECRET_STORE: "test-protected",
      }),
    ).toThrow(/refused in production/i);
  });
});
