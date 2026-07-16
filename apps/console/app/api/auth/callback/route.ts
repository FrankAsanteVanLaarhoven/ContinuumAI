import type { NextRequest } from "next/server";
import { browserAuthUnavailable, getBrowserAuth, toBrowserRequest, toNextResponse } from "../../../../lib/browser-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET /api/auth/callback — atomically consume the S4B transaction, verify, and
 *  issue a secure session cookie only after the full sequence succeeds. */
export async function GET(req: NextRequest) {
  try {
    const { controller } = await getBrowserAuth();
    return toNextResponse(await controller.callback(toBrowserRequest(req)));
  } catch (err) {
    return browserAuthUnavailable(err);
  }
}
