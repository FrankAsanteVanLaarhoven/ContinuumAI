import type { NextRequest } from "next/server";
import { browserAuthUnavailable, getBrowserAuth, toBrowserRequest, toNextResponse } from "../../../../lib/browser-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** POST /api/auth/logout — CSRF-protected, origin-checked. Revokes the server-side
 *  session before clearing the cookies; idempotent. */
export async function POST(req: NextRequest) {
  try {
    const { controller } = await getBrowserAuth();
    return toNextResponse(await controller.logout(toBrowserRequest(req)));
  } catch (err) {
    return browserAuthUnavailable(err);
  }
}
