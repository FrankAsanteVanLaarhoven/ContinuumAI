import { describe, expect, it } from "vitest";
import { digestOf, type EngineExport } from "@continuum/core";
import { adminPool, appPool, dbConfigFromEnv, type DbConfig } from "./pg";
import { migrate } from "./migrate";
import {
  loadEvidence,
  loadPlatformKey,
  persistExport,
  verifyPersistedChain,
} from "./repository";

describe("backup and restore reproduce the evidence digest", () => {
  it("restores the chain into a fresh database with an identical, valid digest", async () => {
    const cfg = dbConfigFromEnv();

    // Back up: read the durable evidence + platform key from the source db.
    const src = appPool(cfg);
    const entries = await loadEvidence(src, "t_acme");
    const platformKey = await loadPlatformKey(src);
    await src.end();
    expect(entries.length).toBeGreaterThan(0);
    const sourceDigest = digestOf(entries);

    // Provision a fresh restore database and migrate it from empty.
    const restoreCfg: DbConfig = { ...cfg, database: "continuum_restore" };
    const admin = adminPool(cfg);
    try {
      await admin.query("DROP DATABASE IF EXISTS continuum_restore");
      await admin.query("CREATE DATABASE continuum_restore");
    } finally {
      await admin.end();
    }
    await migrate(restoreCfg);

    // Restore: re-insert the platform key + evidence chain.
    const dst = appPool(restoreCfg);
    try {
      const backup: EngineExport = {
        platform_public_key_pem: platformKey,
        policy: { policy_version: "restore", risk_threshold: 0.7, capability_ttl_seconds: 90 },
        tenants: [],
        principals: [],
        memory: [],
        consent: [],
        intents: [],
        capabilities: [],
        revoked_handles: [],
        actions: [],
        evidence: entries,
      };
      await persistExport(dst, backup);

      const verification = await verifyPersistedChain(dst, "t_acme");
      expect(verification.valid).toBe(true);

      const restored = await loadEvidence(dst, "t_acme");
      expect(digestOf(restored)).toBe(sourceDigest);
    } finally {
      await dst.end();
    }
  });
});
