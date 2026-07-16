/**
 * Gates 2 & 3 — the console runtime selects the store fail-closed from
 * CONTINUUM_STORE: production requires postgres, refuses memory and refuses an
 * unset value, and never falls back silently.
 */
import { afterEach, describe, expect, it } from "vitest";
import { createRuntime, type Runtime } from "./runtime";

const opened: Runtime[] = [];
function track(rt: Runtime): Runtime {
  opened.push(rt);
  return rt;
}
afterEach(async () => {
  while (opened.length) await opened.pop()!.store.close();
});

// A never-connected Postgres config: PostgresStore builds a lazy pool and does
// not dial until a query, so store SELECTION is testable without a database.
const DUMMY_DB = { host: "127.0.0.1", port: 1, database: "unused" };

describe("console store selection", () => {
  it("memory mode in non-production yields the in-memory adapter", () => {
    const rt = track(createRuntime({ env: { NODE_ENV: "development", CONTINUUM_STORE: "memory" } }));
    expect(rt.mode).toBe("memory");
  });

  it("postgres mode selects the PostgreSQL store", () => {
    const rt = track(
      createRuntime({ env: { NODE_ENV: "production", CONTINUUM_STORE: "postgres" }, dbConfig: DUMMY_DB }),
    );
    expect(rt.mode).toBe("postgres");
  });

  it("REFUSES memory mode in production (no silent fallback)", () => {
    expect(() =>
      createRuntime({ env: { NODE_ENV: "production", CONTINUUM_STORE: "memory" } }),
    ).toThrow(/research-only|refused/i);
  });

  it("REFUSES an unset store selection in production", () => {
    expect(() => createRuntime({ env: { NODE_ENV: "production" } })).toThrow(
      /must be explicitly set to postgres/i,
    );
  });
});
