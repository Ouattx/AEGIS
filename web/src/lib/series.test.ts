import { describe, expect, it } from "vitest";
import { bucketize, chooseBucketHours } from "./series";

describe("bucketize", () => {
  const start = new Date("2026-10-22T00:00:00Z");
  const end = new Date("2026-10-23T00:00:00Z");
  const items = [
    { t: "2026-10-22T00:10:00Z", k: "a" },
    { t: "2026-10-22T05:59:59Z", k: "a" },
    { t: "2026-10-22T06:00:00Z", k: "b" },
    { t: "2026-10-22T23:59:00Z", k: "a" },
    { t: "2026-10-23T00:00:00Z", k: "a" }, // outside (end exclusive)
    { t: "2026-10-22T12:00:00Z", k: "zzz" }, // unknown key
    { t: "bad", k: "a" },
  ];

  it("counts per bucket and key", () => {
    const b = bucketize(items, (x) => x.t, (x) => x.k, ["a", "b"], start, end, 6);
    expect(b.labels).toEqual(["10-22 00h", "10-22 06h", "10-22 12h", "10-22 18h"]);
    expect(b.counts.a).toEqual([2, 0, 0, 1]);
    expect(b.counts.b).toEqual([0, 1, 0, 0]);
  });

  it("uses day labels for daily buckets", () => {
    const b = bucketize(items, (x) => x.t, (x) => x.k, ["a"], start, new Date("2026-10-25T00:00:00Z"), 24);
    expect(b.labels).toEqual(["10-22", "10-23", "10-24"]);
    expect(b.counts.a).toEqual([3, 1, 0]);
  });

  it("chooses a bucket size for about the target count", () => {
    expect(chooseBucketHours(start, new Date("2026-10-25T00:00:00Z"), 24)).toBe(3);
    expect(chooseBucketHours(start, end, 24)).toBe(1);
    expect(chooseBucketHours(start, new Date("2027-10-25T00:00:00Z"), 24)).toBe(168);
  });
});
