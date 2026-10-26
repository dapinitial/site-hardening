// Type surface for blocklist.mjs (site-hardening skill).
export const KNOWN_BAD: string[];
export class Blocklist {
  constructor(opts?: { ranges?: string[]; url?: string | null; everyMs?: number; fetchImpl?: typeof fetch });
  set(ranges: string[]): void;
  readonly size: number;
  refresh(): Promise<boolean>;
  has(ip: string | null | undefined): boolean;
  stop(): void;
}
