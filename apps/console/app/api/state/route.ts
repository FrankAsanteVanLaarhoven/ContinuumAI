import { NextResponse } from "next/server";
import { getConsoleState } from "../../../lib/engine";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json(getConsoleState());
}
