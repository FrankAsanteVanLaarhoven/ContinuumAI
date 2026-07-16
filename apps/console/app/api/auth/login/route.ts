import type { NextRequest } from "next/server";
import { browserAuthUnavailable, getBrowserAuth, toBrowserRequest, toNextResponse } from "../../../../lib/browser-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET /api/auth/login — begin an S4B transaction and redirect to the authorization
 *  server. Fail-closed 503 when browser auth is not configured (e.g. production). */
export async function GET(req: NextRequest) {
  try {
    const { controller } = await getBrowserAuth();
    return toNextResponse(await controller.login(toBrowserRequest(req)));
  } catch (err) {
    return browserAuthUnavailable(err);
  }
}
