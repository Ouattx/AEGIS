import { describe, expect, it } from "vitest";
import { clamp, fmtCompact, fmtNumber, fmtPct, fmtRelative, fmtTime, humanize, localInputToIso, parseCaseTitle, shortDetector, shortHash, shortPseudonym } from "./format";

describe("format", () => {
  it("formats numbers and missing values", () => {
    expect(fmtNumber(1234567)).toBe("1,234,567");
    expect(fmtNumber(1.234, 1)).toBe("1.2");
    expect(fmtNumber(null)).toBe("—");
    expect(fmtNumber(Number.NaN)).toBe("—");
    expect(fmtCompact(248877)).toBe("249k");
    expect(fmtCompact(12345)).toBe("12.3k");
    expect(fmtCompact(2_500_000)).toBe("2.5M");
    expect(fmtCompact(999)).toBe("999");
    expect(fmtPct(0.1818, 1)).toBe("18.2%");
    expect(fmtPct(undefined)).toBe("—");
  });

  it("renders UTC timestamps", () => {
    expect(fmtTime("2026-10-24T19:00:05Z")).toBe("2026-10-24 19:00:05Z");
    expect(fmtTime("2026-10-24T19:00:05Z", false)).toBe("2026-10-24 19:00Z");
    expect(fmtTime("2026-10-24T21:00:05+02:00")).toBe("2026-10-24 19:00:05Z");
    expect(fmtTime("not a date")).toBe("—");
    expect(fmtTime(null)).toBe("—");
  });

  it("renders relative times both ways", () => {
    const now = Date.parse("2026-10-25T12:00:00Z");
    expect(fmtRelative("2026-10-25T11:59:30Z", now)).toBe("30s ago");
    expect(fmtRelative("2026-10-25T11:00:00Z", now)).toBe("1h ago");
    expect(fmtRelative("2026-10-25T06:00:00Z", now)).toBe("6h ago");
    expect(fmtRelative("2026-10-20T12:00:00Z", now)).toBe("5d ago");
    expect(fmtRelative("2026-10-26T12:00:00Z", now)).toBe("in 24h");
  });

  it("shortens hashes, pseudonyms and detector versions", () => {
    const h = "f7aadf565af670026bf812c596282c2f8f552a9e45c820c18c9277dcbdd491f9";
    expect(shortHash(h)).toBe("f7aadf56…91f9");
    expect(shortHash("abc")).toBe("abc");
    expect(shortHash(null)).toBe("—");
    expect(shortPseudonym("p_5e7ad16b758644ea7a77867a3f3396a3")).toBe("p_5e7ad16b…96a3");
    expect(shortDetector("sentinel/1.0.0+sentinel-lgbm-b22c+ioc:2026+872c")).toBe("sentinel/1.0.0");
  });

  it("humanizes identifiers", () => {
    expect(humanize("c2_beaconing")).toBe("C2 beaconing");
    expect(humanize("ROLLED_BACK")).toBe("Rolled back");
    expect(humanize("")).toBe("—");
  });

  it("parses ORACLE case titles", () => {
    expect(parseCaseTitle("ddos_bot on camera device p_5e7a")).toEqual({ label: "ddos_bot", deviceClass: "camera", entity: "p_5e7a" });
    expect(parseCaseTitle("something else")).toBeNull();
  });

  it("converts datetime-local values as UTC", () => {
    expect(localInputToIso("2026-10-22T05:30")).toBe("2026-10-22T05:30:00.000Z");
    expect(localInputToIso("2026-10-22T05:30:15")).toBe("2026-10-22T05:30:15.000Z");
    expect(localInputToIso("")).toBeUndefined();
    expect(localInputToIso("garbage")).toBeUndefined();
    expect(clamp(5, 0, 3)).toBe(3);
  });
});

describe("display labels", () => {
  it("keeps acronyms and curated names", () => {
    expect(humanize("ddos_bot")).toBe("DDoS bot");
    expect(humanize("dga_activity")).toBe("DGA activity");
    expect(humanize("dns_sinkhole")).toBe("DNS sinkhole");
    expect(humanize("c2_beaconing")).toBe("C2 beaconing");
    expect(humanize("ip_block")).toBe("IP block");
    expect(humanize("some_new_label")).toBe("Some new label");
  });
});
