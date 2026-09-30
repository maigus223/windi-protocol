// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import type { RateLimit } from "./types.js";

/** In-memory fixed-window rate limiter. Single process only. */
export class RateLimiter {
  private windows = new Map<string, { start: number; count: number }>();

  /** Returns null if allowed, or the number of seconds to wait. */
  hit(key: string, limit: RateLimit, nowMs: number): number | null {
    const w = this.windows.get(key);
    const windowMs = limit.windowSeconds * 1000;
    if (!w || nowMs - w.start >= windowMs) {
      this.windows.set(key, { start: nowMs, count: 1 });
      this.gc(nowMs, windowMs);
      return null;
    }
    if (w.count >= limit.max) return Math.max(1, Math.ceil((w.start + windowMs - nowMs) / 1000));
    w.count += 1;
    return null;
  }

  private gc(nowMs: number, windowMs: number): void {
    if (this.windows.size < 10_000) return;
    for (const [k, w] of this.windows) if (nowMs - w.start >= windowMs) this.windows.delete(k);
  }
}
