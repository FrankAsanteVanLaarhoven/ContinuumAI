import type { NextRequest } from "next/server";
import { browserAuthUnavailable, getBrowserAuth, toBrowserRequest, toNextResponse } from "../../../../lib/browser-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** POST /api/auth/csrf — issue a session-bound CSRF token to an authenticated,
 *  same-origin caller. */
export async function POST(req: NextRequest) {
  try {
    const { controller } = await getBrowserAuth();
    return toNextResponse(await controller.csrf(toBrowserRequest(req)));
  } catch (err) {
    return browserAuthUnavailable(err);
  }
}
