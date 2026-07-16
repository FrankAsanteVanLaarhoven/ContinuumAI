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
import { provisionForExport, serviceRef } from "../test/identity";

describe("backup and restore reproduce the evidence digest", () => {
  it("restores the chain into a fresh database with an identical, valid digest", async () => {
    const cfg = dbConfigFromEnv();

    // Back up: read the durable evidence + platform key from the source db.
    const src = appPool(cfg);
    const entries = await loadEvidence(src, serviceRef("t_acme"));
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

    // Restore: re-insert the platform key + evidence chain. Provision the trusted
    // service identity for the tenant in the fresh db first (admin path), so the
    // S2B RLS admits the restore writes and the re-verification reads.
    const dst = appPool(restoreCfg);
    const restoreAdmin = adminPool(restoreCfg);
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
      const resolveRef = await provisionForExport(restoreAdmin, backup);
      await persistExport(dst, backup, resolveRef);

      const verification = await verifyPersistedChain(dst, serviceRef("t_acme"));
      expect(verification.valid).toBe(true);

      const restored = await loadEvidence(dst, serviceRef("t_acme"));
      expect(digestOf(restored)).toBe(sourceDigest);
    } finally {
      await dst.end();
      await restoreAdmin.end();
    }
  });
});
