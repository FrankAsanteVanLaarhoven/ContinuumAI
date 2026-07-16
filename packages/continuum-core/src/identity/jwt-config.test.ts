/** S4A — verifier configuration guards: vendor-neutral and fail-closed. */
import { describe, expect, it } from "vitest";
import {
  assertProductionJwtConfig,
  resolveJwksProviderMode,
  resolveJwtVerifierMode,
  resolveReplayStoreMode,
} from "./index";

describe("S4A config guards", () => {
  it("requires the real jwt verifier in production; refuses the deterministic one", () => {
    expect(resolveJwtVerifierMode({ CONTINUUM_IDENTITY_VERIFIER: "jwt" })).toBe("jwt");
    expect(resolveJwtVerifierMode({ NODE_ENV: "development", CONTINUUM_IDENTITY_VERIFIER: "deterministic" })).toBe("deterministic");
    expect(() => resolveJwtVerifierMode({ NODE_ENV: "production", CONTINUUM_IDENTITY_VERIFIER: "deterministic" })).toThrow(/refused in production/i);
    expect(() => resolveJwtVerifierMode({ NODE_ENV: "production" })).toThrow(/must be set to 'jwt'/i);
    expect(() => resolveJwtVerifierMode({ NODE_ENV: "development" })).toThrow(/must be set/i);
  });

  it("requires the cached JWKS provider in production; refuses fixture/local-http", () => {
    expect(resolveJwksProviderMode({ CONTINUUM_JWKS_PROVIDER: "cached" })).toBe("cached");
    expect(resolveJwksProviderMode({ NODE_ENV: "test", CONTINUUM_JWKS_PROVIDER: "fixture" })).toBe("fixture");
    expect(() => resolveJwksProviderMode({ NODE_ENV: "production", CONTINUUM_JWKS_PROVIDER: "local_http" })).toThrow(/refused in production/i);
    expect(() => resolveJwksProviderMode({ NODE_ENV: "production" })).toThrow(/must be set to 'cached'/i);
  });

  it("requires the postgres replay store in production when replay is enabled", () => {
    expect(resolveReplayStoreMode({ CONTINUUM_REPLAY_STORE: "postgres" }, { replayEnabled: true })).toBe("postgres");
    expect(resolveReplayStoreMode({ NODE_ENV: "development", CONTINUUM_REPLAY_STORE: "memory" }, { replayEnabled: true })).toBe("memory");
    expect(resolveReplayStoreMode({ CONTINUUM_REPLAY_STORE: "none" }, { replayEnabled: false })).toBe("none");
    expect(() => resolveReplayStoreMode({ CONTINUUM_REPLAY_STORE: "none" }, { replayEnabled: true })).toThrow(/enables replay/i);
    expect(() => resolveReplayStoreMode({ NODE_ENV: "production", CONTINUUM_REPLAY_STORE: "memory" }, { replayEnabled: true })).toThrow(/refused in production/i);
    expect(() => resolveReplayStoreMode({ NODE_ENV: "production" }, { replayEnabled: true })).toThrow(/postgres/i);
  });

  it("production startup guard passes only with jwt + cached + postgres", () => {
    expect(() => assertProductionJwtConfig({ NODE_ENV: "development" })).not.toThrow();
    expect(() =>
      assertProductionJwtConfig({
        NODE_ENV: "production", CONTINUUM_IDENTITY_VERIFIER: "jwt", CONTINUUM_JWKS_PROVIDER: "cached", CONTINUUM_REPLAY_STORE: "postgres",
      }),
    ).not.toThrow();
    expect(() =>
      assertProductionJwtConfig({
        NODE_ENV: "production", CONTINUUM_IDENTITY_VERIFIER: "deterministic", CONTINUUM_JWKS_PROVIDER: "cached", CONTINUUM_REPLAY_STORE: "postgres",
      }),
    ).toThrow(/deterministic/i);
  });
});
