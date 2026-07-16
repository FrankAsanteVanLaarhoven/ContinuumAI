import { NextResponse } from "next/server";
import { createRuntime, getRuntimeState, resolveConsoleContext } from "../../../lib/runtime";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * The real console/API path over the async engine. Store selection is fail-closed
 * (CONTINUUM_STORE); tenant authority is derived by the trusted boundary. A store
 * or database failure surfaces as a 503 — never a silent fallback to memory.
 */
export async function GET() {
  let rt;
  try {
    rt = createRuntime();
  } catch (err) {
    return NextResponse.json(
      { error: "runtime_unavailable", detail: (err as Error).message },
      { status: 503 },
    );
  }
  try {
    const ctx = await resolveConsoleContext(rt);
    return NextResponse.json(await getRuntimeState(rt, ctx));
  } catch (err) {
    return NextResponse.json(
      { error: "runtime_error", detail: (err as Error).message },
      { status: 503 },
    );
  } finally {
    await rt.store.close();
  }
}
