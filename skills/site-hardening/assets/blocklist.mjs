// blocklist.mjs — one blocklist for the whole fleet.
//
// A range that attacks one site attacks the next one tomorrow, so the list is shared, not
// per-app. Each app loads the same JSON (an array of CIDR strings) from BLOCKLIST_URL, refreshed
// hourly, on top of the known-bad ranges below. Serve the JSON from anywhere every app can read:
// a file in a public bucket, a route on the comms relay, a Supabase table with a public read
// policy. Adding a range there blocks it everywhere within the hour, with no deploys.
//
// Usage:
//   import { Blocklist } from './blocklist.mjs';
//   const block = new Blocklist({ url: process.env.BLOCKLIST_URL });
//   if (block.has(clientIp(req))) return drop('blocked range');

/** Ranges confirmed abusive against the fleet. Date and reason on every line; prune when quiet
 * for 90 days. All five: IPXO-leased, "Private Customer" in RIPE, announced by AS3320, located in
 * Frankfurt; the 2026-09/10 headless-Chromium form relay botnet (2,126 attempts). */
export const KNOWN_BAD = [
  '95.134.16.0/22',    // 2026-09-17 unakin.com intake relay botnet
  '95.134.224.0/22',   // 2026-09-17 same
  '178.92.172.0/22',   // 2026-09-17 same
  '82.26.168.0/24',    // 2026-10-21 same operator, new range
  '151.242.93.0/24',   // 2026-10-22 same operator, new range
];

const v4 = (ip) => { const o = ip.split('.'); if (o.length !== 4) return null; let n = 0; for (const s of o) { const b = Number(s); if (!Number.isInteger(b) || b < 0 || b > 255) return null; n = n * 256 + b; } return n; };
const v6 = (ip) => {
  if (!ip.includes(':')) return null;
  let [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  if (!ip.includes('::') && h.length !== 8) return null;
  const parts = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  if (parts.length !== 8) return null;
  let n = 0n; for (const p of parts) { const x = parseInt(p || '0', 16); if (Number.isNaN(x) || x > 0xffff) return null; n = (n << 16n) + BigInt(x); }
  return n;
};
function parseCidr(cidr) {
  const [addr, bitsStr] = String(cidr).trim().split('/');
  const is6 = addr.includes(':');
  const bits = bitsStr === undefined ? (is6 ? 128 : 32) : Number(bitsStr);
  if (is6) { const n = v6(addr); if (n === null || bits < 0 || bits > 128) return null; const mask = bits === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n); return { is6, base: n & mask, mask }; }
  const n = v4(addr); if (n === null || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { is6, base: (n & mask) >>> 0, mask };
}

export class Blocklist {
  #ranges = []; #url; #every; #timer;
  constructor({ ranges = KNOWN_BAD, url = null, everyMs = 3_600_000, fetchImpl = globalThis.fetch } = {}) {
    this.#url = url; this.#every = everyMs; this.fetch = fetchImpl;
    this.set(ranges);
    if (url) { this.refresh().catch(() => {}); this.#timer = setInterval(() => this.refresh().catch(() => {}), everyMs); this.#timer.unref?.(); }
  }
  /** Replace the list (the known-bad ranges stay). */
  set(ranges) { this.#ranges = [...new Set([...KNOWN_BAD, ...ranges])].map(parseCidr).filter(Boolean); }
  get size() { return this.#ranges.length; }
  /** Load the shared JSON array; on any failure the current list stays. */
  async refresh() {
    if (!this.#url) return false;
    const res = await this.fetch(this.#url, { signal: AbortSignal.timeout(8_000) });
    if (!res.ok) throw new Error(`blocklist ${res.status}`);
    const list = await res.json();
    if (!Array.isArray(list)) throw new Error('blocklist is not an array');
    this.set(list.filter((x) => typeof x === 'string'));
    return true;
  }
  has(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const is6 = ip.includes(':'); const n = is6 ? v6(ip) : v4(ip);
    if (n === null) return false;
    return this.#ranges.some((r) => r.is6 === is6 && (is6 ? (n & r.mask) === r.base : ((n & r.mask) >>> 0) === r.base));
  }
  stop() { clearInterval(this.#timer); }
}
