/** Time bucketing for trend charts. */

export interface Bucketed {
  labels: string[];
  starts: number[];
  counts: Record<string, number[]>;
}

const pad = (n: number) => String(n).padStart(2, "0");

/**
 * Count items per ``bucketHours`` bucket between ``start`` and ``end`` (UTC), split by
 * ``keyOf``. Items outside the range are ignored. Labels are ``MM-DD HH:00`` (or
 * ``MM-DD`` for daily buckets).
 */
export function bucketize<T>(
  items: T[],
  timeOf: (t: T) => string | null | undefined,
  keyOf: (t: T) => string,
  keys: string[],
  start: Date,
  end: Date,
  bucketHours: number,
): Bucketed {
  const step = bucketHours * 3600_000;
  const s0 = Math.floor(start.getTime() / step) * step;
  const n = Math.max(1, Math.ceil((end.getTime() - s0) / step));
  const starts = Array.from({ length: n }, (_, i) => s0 + i * step);
  const counts: Record<string, number[]> = {};
  for (const k of keys) counts[k] = new Array(n).fill(0);
  for (const it of items) {
    const ts = timeOf(it);
    if (!ts) continue;
    const t = new Date(ts).getTime();
    if (Number.isNaN(t) || t < s0 || t >= s0 + n * step) continue;
    const k = keyOf(it);
    if (!counts[k]) continue;
    counts[k][Math.floor((t - s0) / step)] += 1;
  }
  const labels = starts.map((ms) => {
    const d = new Date(ms);
    const day = `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    return bucketHours >= 24 ? day : `${day} ${pad(d.getUTCHours())}h`;
  });
  return { labels, starts, counts };
}

/** Pick a bucket size giving roughly ``target`` buckets over the range. */
export function chooseBucketHours(start: Date, end: Date, target = 24): number {
  const hours = Math.max(1, (end.getTime() - start.getTime()) / 3600_000);
  const options = [1, 2, 3, 4, 6, 12, 24, 48, 168];
  for (const o of options) if (hours / o <= target) return o;
  return 168;
}
