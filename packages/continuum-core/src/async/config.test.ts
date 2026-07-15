import { describe, it, expect } from "vitest";
import { resolveStoreMode, assertProductionStore, storeClassification, isProduction } from "./config";
import { RESEARCH_ONLY } from "./context";

function env(overrides: Record<string, string | undefined>): NodeJS.ProcessEnv {
  return overrides as NodeJS.ProcessEnv;
}

describe("store-selection gate", () => {
  it("defaults to memory outside production when unset", () => {
    expect(resolveStoreMode(env({}))).toBe("memory");
    expect(resolveStoreMode(env({ NODE_ENV: "development" }))).toBe("memory");
  });

  it("selects postgres when explicitly set", () => {
    expect(resolveStoreMode(env({ CONTINUUM_STORE: "postgres" }))).toBe("postgres");
    expect(resolveStoreMode(env({ NODE_ENV: "production", CONTINUUM_STORE: "postgres" }))).toBe("postgres");
  });

  it("PRODUCTION refuses an unset store", () => {
    expect(() => resolveStoreMode(env({ NODE_ENV: "production" }))).toThrow(/must be explicitly set to postgres/i);
  });

  it("PRODUCTION refuses an invalid store value", () => {
    expect(() => resolveStoreMode(env({ NODE_ENV: "production", CONTINUUM_STORE: "sqlite" }))).toThrow(/postgres/i);
  });

  it("PRODUCTION refuses memory mode explicitly (no research store in prod)", () => {
    expect(() => resolveStoreMode(env({ NODE_ENV: "production", CONTINUUM_STORE: "memory" }))).toThrow(/research-only/i);
  });

  it("assertProductionStore refuses memory mode in production (no silent fallback)", () => {
    expect(() => assertProductionStore(env({ NODE_ENV: "production" }), "memory")).toThrow(/requires CONTINUUM_STORE=postgres/i);
    expect(() => assertProductionStore(env({ NODE_ENV: "production" }), "postgres")).not.toThrow();
    expect(() => assertProductionStore(env({ NODE_ENV: "development" }), "memory")).not.toThrow();
  });

  it("memory mode is classified RESEARCH_ONLY", () => {
    expect(storeClassification("memory")).toBe(RESEARCH_ONLY);
    expect(storeClassification("postgres")).toBe("PRODUCTION_CANDIDATE");
    expect(isProduction(env({ NODE_ENV: "production" }))).toBe(true);
  });
});
