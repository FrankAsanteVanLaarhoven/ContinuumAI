/**
 * Phase 3 S4C — browser-auth evidence (redacted; safe identifiers + keyed digests).
 *
 * Never recorded: raw cookies, raw state/code/nonce, PKCE verifier, identity token,
 * CSRF secret, session credential, or the full callback URL. Only stable ids
 * (principal/session) and keyed digests (e.g. of the login correlation reference)
 * appear here.
 */
import type { RequestId } from "../async/context";

export type BrowserAuthEventType =
  | "browser.login_initiated"
  | "browser.callback_accepted"
  | "browser.callback_denied"
  | "browser.session_issued"
  | "browser.session_validation_denied"
  | "browser.csrf_denied"
  | "browser.logout_completed"
  | "browser.host_denied"
  | "browser.session_rotated";

export interface BrowserAuthEvent {
  readonly type: BrowserAuthEventType;
  readonly at: Date;
  readonly requestId: RequestId;
  readonly outcome: "success" | "denied";
  readonly reason: string | null;
  readonly principalId: string | null;
  readonly sessionId: string | null;
  /** Keyed digest of the login correlation reference, if any. Never the raw value. */
  readonly correlationDigest: string | null;
}

export interface BrowserAuthEventSink {
  append(event: BrowserAuthEvent): Promise<void>;
}

/** Dev/test in-memory sink. */
export class InMemoryBrowserAuthEventSink implements BrowserAuthEventSink {
  readonly events: BrowserAuthEvent[] = [];
  async append(event: BrowserAuthEvent): Promise<void> {
    this.events.push(event);
  }
}
