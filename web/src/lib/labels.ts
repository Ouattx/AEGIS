/**
 * Display names for machine labels (threat classes, action types, device classes).
 * Mirrors ``aegis/reports/labels.py`` so the console and the PoV report read the same:
 * "DDoS bot", "DNS sinkhole", never "Ddos bot".
 */
export const DISPLAY_NAMES: Record<string, string> = {
  c2_beaconing: "C2 beaconing",
  ddos_bot: "DDoS bot",
  dga_activity: "DGA activity",
  residential_proxy: "Residential proxy",
  known_bad_contact: "Known-bad contact",
  suspicious_activity: "Suspicious activity",
  dns_sinkhole: "DNS sinkhole",
  ip_block: "IP block",
  device_quarantine: "Device quarantine",
  notify_subscriber: "Subscriber notification",
  android_tv: "Android TV box",
  smart_tv: "Smart TV",
  iptv_box: "IPTV box",
  console: "Game console",
  phone: "Phone",
  laptop: "Laptop",
  camera: "IoT camera",
};

const ACRONYMS: Record<string, string> = {
  dns: "DNS", ip: "IP", ddos: "DDoS", dga: "DGA", c2: "C2", tv: "TV", iot: "IoT", vpn: "VPN", cdn: "CDN",
  iptv: "IPTV", rpz: "RPZ", nxdomain: "NXDOMAIN", ioc: "IOC", llm: "LLM",
};

/** Curated display name, else a sentence-case rendering that keeps acronyms. */
export function displayLabel(s: string | null | undefined): string {
  if (!s) return "—";
  const key = s.trim();
  if (DISPLAY_NAMES[key]) return DISPLAY_NAMES[key];
  const words = key.replace(/[_-]+/g, " ").trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return "—";
  const out = words.map((w) => ACRONYMS[w] ?? w);
  const first = out[0];
  out[0] = ACRONYMS[words[0]] ? first : first.charAt(0).toUpperCase() + first.slice(1);
  return out.join(" ");
}
