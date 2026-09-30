// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import { appendFileSync } from "node:fs";
import type { AuditEntry, AuditSink } from "./types.js";

export class MemoryAudit implements AuditSink {
  readonly entries: AuditEntry[] = [];
  write(entry: AuditEntry): void {
    this.entries.push(entry);
  }
  /** Retention helper: drop entries older than `days`. */
  prune(days: number, now = Date.now()): number {
    const cutoff = now - days * 86_400_000;
    const before = this.entries.length;
    const kept = this.entries.filter((e) => Date.parse(e.timestamp) >= cutoff);
    this.entries.length = 0;
    this.entries.push(...kept);
    return before - kept.length;
  }
}

/** Appends one JSON object per line. Retention of the file is the site's responsibility. */
export class JsonlAudit implements AuditSink {
  constructor(private readonly path: string) {}
  write(entry: AuditEntry): void {
    appendFileSync(this.path, JSON.stringify(entry) + "\n", "utf8");
  }
}
