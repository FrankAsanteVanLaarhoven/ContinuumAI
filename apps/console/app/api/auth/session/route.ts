import type { NextRequest } from "next/server";
import { browserAuthUnavailable, getBrowserAuth, toBrowserRequest, toNextResponse } from "../../../../lib/browser-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET /api/auth/session — report the authenticated principal (NO tenant, NO
 *  credential). Reads only; never mutates state. */
export async function GET(req: NextRequest) {
  try {
    const { controller } = await getBrowserAuth();
    return toNextResponse(await controller.session(toBrowserRequest(req)));
  } catch (err) {
    return browserAuthUnavailable(err);
  }
}
