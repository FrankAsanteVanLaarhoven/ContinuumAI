import { NextResponse } from "next/server";
import { rerunSlice } from "../../../lib/engine";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function POST() {
  return NextResponse.json(rerunSlice());
}
