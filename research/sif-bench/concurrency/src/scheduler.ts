/**
 * Deterministic synchronization primitives for the concurrency suite.
 *
 * Interleavings are forced with barriers, latches, and controlled promises — not
 * timing sleeps — so the same seed reproduces the same schedule and the same
 * verdict. Latency is measured but never used to decide an interleaving.
 */

/** Seeded PRNG (mulberry32). Deterministic; used only to vary labels/order, never timing. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export class Deferred<T> {
  readonly promise: Promise<T>;
  resolve!: (v: T | PromiseLike<T>) => void;
  reject!: (e: unknown) => void;
  constructor() {
    this.promise = new Promise<T>((res, rej) => {
      this.resolve = res;
      this.reject = rej;
    });
  }
}

/** A one-shot latch: many waiters block until `open()` is called once. */
export class Latch {
  private readonly d = new Deferred<void>();
  private opened = false;
  wait(): Promise<void> {
    return this.d.promise;
  }
  open(): void {
    if (!this.opened) {
      this.opened = true;
      this.d.resolve();
    }
  }
}

/** A barrier: the Nth `arrive()` releases all N parties simultaneously. */
export class Barrier {
  private readonly d = new Deferred<void>();
  private count = 0;
  constructor(private readonly parties: number) {}
  async arrive(): Promise<void> {
    this.count += 1;
    if (this.count >= this.parties) this.d.resolve();
    return this.d.promise;
  }
}

/**
 * Records the observed execution order of labeled steps. Two workers append as
 * they progress; the resulting sequence is the case's interleaving witness.
 */
export class ScheduleRecorder {
  private readonly steps: string[] = [];
  mark(label: string): void {
    this.steps.push(label);
  }
  sequence(): string[] {
    return [...this.steps];
  }
}

/** Millisecond wall-clock for latency only (never for ordering). */
export function nowPerf(): number {
  return globalThis.performance.now();
}
