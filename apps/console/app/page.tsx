import { getConsoleState } from "../lib/engine";
import { Console } from "./console";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export default function Page() {
  const state = getConsoleState();
  return <Console initial={state} />;
}
