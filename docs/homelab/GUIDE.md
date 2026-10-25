# AEGIS Home Lab Kit: testing one streaming box at home

This guide is for one person testing **one streaming box (Android TV box, IPTV box, stick) that
they own**, at home, to see what it talks to on the network. It covers how to do it safely, what
the law allows (with notes for France and the EU), how to read the result honestly, and what to
do if you find something.

Short version:

* the box goes on its **own isolated Wi-Fi**, never on your home network;
* you record **traffic metadata only** (who, when, how much), never content;
* the box gets **no personal account**, and the test has a **time limit**;
* you **never use pirate IPTV services** to "exercise" it;
* a timer or a domain is **not proof**; you **do not name** a vendor or seller publicly without
  proof that would hold up, and you go through **responsible disclosure** first.

Nothing in this guide is legal advice. Have a lawyer review anything you intend to publish.

## Contents

1. [What the kit does](#1-what-the-kit-does)
2. [Safety](#2-safety)
3. [Legality](#3-legality)
4. [Running the lab](#4-running-the-lab)
5. [Reading the Box Lab report](#5-reading-the-box-lab-report)
6. [Responsible disclosure](#6-responsible-disclosure)
7. [No naming without proof](#7-no-naming-without-proof)
8. [Data handling](#8-data-handling)
9. [Limitations](#9-limitations)

## 1. What the kit does

```
 device under test ))) lab Wi-Fi (isolated) ── Raspberry Pi or laptop ── your router ── internet
                        10.42.0.0/24             hostapd + dnsmasq (DNS log)
                                                 nftables: NAT, no LAN, rate cap
                                                 tcpdump -s 96 (headers only)
                                                         │ offline
                                                 Zeek conn.log / dns.log
                                                         │
                                  python -m aegis.homelab analyze  ──>  Box Lab report (HTML)
```

* `deploy/homelab/`: setup scripts for a Raspberry Pi access point, a Linux laptop hotspot and
  a macOS Internet Sharing variant; header-only capture with rotation and a hard time limit;
  offline Zeek conversion; teardown. See [deploy/homelab/README.md](../../deploy/homelab/README.md).
* `aegis/homelab/`: imports the capture into the regular AEGIS ingest pipeline with a
  "single-home" source configuration, runs the per-device detectors (SENTINEL), a timer and
  heartbeat analysis with periodograms, compares behavior while you use the box and while it
  sits idle, lists contacted infrastructure with signed threat-feed matches, applies a
  pre-registered verdict policy and writes every piece of evidence, with its sha256, into a
  signed hash-chained ledger next to the report.
* Optional **crowd mixing** shows what AEGIS's cross-subscriber detector (RESONANCE) would see if
  many homes had the same box. It is **mixed synthetic data** and is labelled so everywhere.

## 2. Safety

Assume the box may be compromised before you open the packaging (pre-infected firmware has been
documented on cheap Android TV boxes). Design the test so that a compromised box can harm nothing.

**Isolation**

* The box joins **only the lab Wi-Fi**. Never connect it to your home Wi-Fi or Ethernet, not even
  "for a minute" to update it.
* The lab firewall blocks the box from reaching your home network (all private address ranges),
  the lab gateway itself (except DHCP and DNS), other lab clients (client isolation at Wi-Fi and IP
  level) and IPv6. Check it once: from a phone joined to the lab, your router's admin page and your
  NAS must be unreachable.
* Connect **one device under test at a time**. Do not join your own phone or laptop to the lab
  except briefly to check isolation, then forget the network.
* Do not plug USB drives, cameras or keyboards with stored data into the box.

**No personal accounts**

* Do not sign in to any Google, Amazon, streaming, email or payment account on the box. Do not
  type any password you use elsewhere. If an app insists on an account, skip that app.
* Do not cast to the box from your phone (casting pairs your phone with it).
* After the test, **factory reset** the box. If you keep using it, keep it on the lab network.

**Time limits**

* Captures stop by themselves after `MAX_HOURS` (72 h by default, at most two weeks). One to three
  days are enough to see daily timers and idle behavior.
* Power the box off when you are not testing.

**Your internet connection may be used by malware**

Compromised TV boxes are commonly rented out as **residential proxies** or used for click fraud or
attacks. While the box is online, traffic leaving your connection may not be yours.

* Keep the **rate cap** on (`EGRESS_RATE_KBYTES`, 500 kB/s each way by default): it limits what
  can be done through your connection.
* Keep tests short. If your ISP or a service warns you about abuse from your connection, unplug
  the box, keep the capture and mention the test when you answer (this is why you keep notes).
* The kit never connects to, scans or probes the servers the box contacts. Do not do it yourself
  either (see Legality).

## 3. Legality

*Not legal advice. Laws differ between countries; the notes below concern France and the EU and
must be checked by counsel for your situation, especially before publishing anything.*

**Test the device only.** Observe traffic of a device you own, on a network you control.

* Capturing other people's communications is an offence in many countries. In France,
  intercepting correspondence sent electronically is punished by the Code pénal (art. 226-15),
  and the EU ePrivacy Directive (2002/58/EC, art. 5) protects the confidentiality of
  communications. The lab network carries only your test device: keep it that way.
* Accessing or probing someone else's information system without authorization is an offence
  (France: Code pénal art. 323-1 and following). Passive observation of your own device's traffic
  is the whole scope of this kit: never log in to, scan, "test" or disrupt a server the box
  contacts, even if it looks malicious.
* Do not modify, root or reflash the box for this test; firmware reverse engineering raises
  separate questions (EU Software Directive 2009/24/EC, art. 6) and is out of scope.

**Metadata only.** The capture keeps 96 bytes per packet (link, IP and transport headers); the
scripts refuse more than 128. There is no payload capture and no TLS decryption. The dnsmasq log
records the names the box looks up. In a purely personal setting, processing data about your own
device and household is generally outside the GDPR (household exemption, art. 2(2)(c)); it is
not if other people's data ends up in the capture or if you share it beyond personal use, so do
not let others use the lab network and pseudonymize what you share.

**Do not use pirate IPTV services.** Do not subscribe to, install or stream from unlicensed IPTV
services, "loaded" app stores or add-ons to make the box generate traffic. Watching unlicensed
streams is copyright infringement in the EU (CJEU, C-527/15 *Stichting Brein v Filmspeler*, 2017,
held that streaming from an illegal source is not covered by the temporary-copy exception), and in
France it falls under the Code de la propriété intellectuelle, enforced by Arcom. It is also not
needed: the most telling behavior is what the box does **while idle**, with its stock launcher, or
with legitimate free apps. Write down what you installed.

**Radio.** Set `COUNTRY_CODE` to your country so the access point follows local Wi-Fi rules.

**Publishing.** Accusing a company or a person publicly can be defamation (France: law of
29 July 1881, art. 29). Read [No naming without proof](#7-no-naming-without-proof) and have
counsel review any publication.

## 4. Running the lab

### Raspberry Pi (recommended)

A Raspberry Pi 4 or 5 with Raspberry Pi OS (Bookworm), connected to your router by Ethernet; its
built-in Wi-Fi becomes the lab access point.

```bash
cd deploy/homelab
cp homelab.env.example homelab.env      # set LAB_PASSPHRASE (12+ characters) and COUNTRY_CODE
sudo ./setup-ap.sh                      # idempotent: re-run after any change to homelab.env
```

Join the box to the `aegis-lab` network, then start a capture:

```bash
sudo ./capture.sh start box1            # header-only, rotates hourly, stops after MAX_HOURS
# ... use the box normally for a while, then leave it idle (screen off / standby) ...
sudo ./capture.sh stop                  # also copies the dnsmasq query log into the capture
./zeek-convert.sh /var/lib/aegis-homelab/captures/box1    # needs Zeek; can run on a laptop
```

### Linux laptop

A laptop with NetworkManager, a Wi-Fi adapter that supports access-point mode and **another**
uplink (Ethernet or a second Wi-Fi adapter). Set `LAB_IFACE` and `UPLINK_IFACE` in `homelab.env`.

```bash
sudo ./laptop-hotspot-linux.sh start    # hotspot with client isolation, logged DNS, same firewall
sudo ./capture.sh start box1
sudo ./capture.sh stop
sudo ./laptop-hotspot-linux.sh stop
```

NetworkManager's dnsmasq writes timestamps in the laptop's local time; the capture manifest
records that timezone and the analyzer uses it.

### macOS

Turn on Internet Sharing (Ethernet to Wi-Fi, with a password) in System Settings, join only the
box, then `sudo ./laptop-hotspot-macos.sh start box1` and `stop`. There is no Wi-Fi client
isolation and no dnsmasq on macOS: DNS comes from a separate port-53 capture (512 bytes per
packet), and you must pass the sharing network to the analyzer
(`--subnet 192.168.2.0/24 --gateway 192.168.2.1`).

### Note when you use the box

The analysis compares what the box does while you use it with what it does while idle. Write
down your sessions in `usage.json` in the capture directory (times with a timezone):

```json
{"active": [["2026-10-20T19:00:00+02:00", "2026-10-20T21:30:00+02:00"],
            ["2026-10-21T08:15:00+02:00", "2026-10-21T08:45:00+02:00"]]}
```

Everything else in the capture counts as idle. You may list idle periods explicitly with an
`"idle"` key, or use a CSV with the header `start,end,state`. Without notes, the report says the
comparison is unavailable rather than guessing it.

### Analyze

```bash
python -m aegis.homelab analyze /var/lib/aegis-homelab/captures/box1 --out ./box1-report \
    --label 10.42.0.23="living-room box"
# optional: a signed AEGIS IOC bundle (verified, refused if the signature fails)
#   --ioc-bundle feed.json --ioc-pubkey feed-signer.pem --ioc-key-id <key id>
# optional: a plain list of domains/IPs you want flagged for orientation (never evidence)
#   --local-list mylist.txt
# optional: crowd mixing (MIXED-SYNTHETIC demonstration of RESONANCE)
#   --crowd 20
python -m aegis.homelab verify ./box1-report          # re-verify the signed evidence ledger
```

To try the whole chain without any device: `python -m aegis.homelab synthetic ./demo-capture`
writes a capture of a fictional box (every report built from it carries a SYNTHETIC banner).

When you are done: `sudo ./teardown.sh` (add `--purge-captures` once you no longer need the data)
and factory-reset the box.

## 5. Reading the Box Lab report

The report has one verdict per device, produced by a pre-registered policy that is the same for
everyone and never declares a device clean:

| verdict | meaning |
|---|---|
| **MALICIOUS (review)** | a signed threat feed lists a destination the box really contacted, **and** the box's own behavior on that destination (a timer, or a detector alert) corroborates it: two independent origins. Still requires human review. |
| **SUSPICIOUS** | one strong signal (a verified feed match, or a SENTINEL alert), not corroborated. |
| **NO CONCLUSION** | nothing strong enough. The report lists weak signals worth a look (timers that keep running while idle, failed lookups, addresses contacted without a lookup, direct use of outside resolvers). |

How to read the parts:

* **Heartbeats.** Many legitimate services poll on timers: time sync, connectivity checks, push
  notifications, app telemetry. A timer is a reason to look, not a finding. Timers that follow your
  viewing sessions are usually app heartbeats; timers that run around the clock while the box sits
  idle deserve attention, especially toward unfamiliar destinations. z values are nominal, not
  calibrated.
* **Feed matches.** Only a signed, active, uncontradicted indicator with real traffic to it counts as
  a witness. Several feeds repeating one report count as one origin.
* **SENTINEL.** The detectors were trained on synthetic data at operator vantage; on a single home
  device their scores are indicative only. A "benign" window only means no detector fired.
* **Crowd mixing.** Every copy is the same box, so all of its timers, benign ones included, resonate.
  It shows what would be *detectable* across homes, not that the box is malicious.
* **Evidence trail.** Each item has a sha256 and a ledger entry; `verify` re-checks the chain.
  Keep the report directory intact if you may need to show your work.

## 6. Responsible disclosure

If the report shows something worth acting on (typically a verified feed match, or idle timers to
unfamiliar dedicated hosts that you can reproduce):

1. **Preserve.** Keep the capture directory, the report directory (report, `analysis.json`, ledger
   database, `keys/`) and your notes (purchase date and place, model and firmware shown in the
   settings, apps installed). Do not edit them; re-run the analysis into a new directory if needed.
2. **Reproduce.** Ideally a second capture, on another day, after a factory reset. A second unit of
   the same model bought elsewhere is stronger still.
3. **Write a factual summary.** What you observed, when, on which unit, with the method's limits.
   No conclusions about intent or about who is responsible.
4. **Report**, privately and in parallel where it makes sense:
   * the **manufacturer's security contact** (look for `/.well-known/security.txt` on their site, a
     PSIRT page, or the support channel);
   * **CERT-FR** (ANSSI's national CSIRT, contact details on cert.ssi.gouv.fr), or your country's
     national CSIRT. Under the EU Cyber Resilience Act, manufacturers of connected products sold in
     the EU must report actively exploited vulnerabilities to CSIRTs and ENISA, so a national CSIRT
     is the right counterpart;
   * the **marketplace or shop** that sold the box, through its product-safety or report-a-product
     channel; in France, consumer product problems can also be reported on SignalConso (DGCCRF);
   * **your ISP's abuse team** if you believe the box used your connection for abuse.
5. **Wait.** Give the vendor time to respond and fix: 90 days is the usual coordinated-disclosure
   period. Agree a shorter or longer period with the CSIRT when people are actively being harmed or
   when a fix needs more time.
6. **Publish carefully, if at all.** Facts and method, not accusations; no indicators that would
   help others abuse infected devices; counsel review first (see next section).

## 7. No naming without proof

The principle: **no one is judged on a single source**, and we never claim more than we can prove.
One home capture of one unit is one source.

What a single capture supports, worded as an observation:

> "In my home lab on 20 to 22 October 2026, a box sold as model X, firmware Y, bought from shop Z,
> contacted `example-domain` about every 10 minutes while idle. The domain is listed by feed F as
> command-and-control infrastructure."

What it does **not** support:

* "Brand X ships malware" or "shop Z sells infected boxes": a model name can cover many hardware
  and firmware variants, clones and counterfeits; the seller may not be the manufacturer; one unit
  is not a product line.
* Anything about intent, or naming a person.

Before naming a company or a seller publicly, you need at least: reproduction on more than one
unit (ideally from different sources), an independent confirmation (a national CSIRT, the vendor,
a reputable security team, or published research), the vendor's chance to answer during the
disclosure period, and legal review. Until then, refer to the device by what it is ("an Android TV
box bought online in 2026") and share details privately with the CSIRT and the vendor.

## 8. Data handling

* Captures contain the domains your box looked up and the addresses it contacted, with times. Keep
  them on an encrypted disk, share them only with the parties in [section 6](#6-responsible-disclosure),
  and delete them (`teardown.sh --purge-captures`) when the matter is closed.
* Reports identify devices by pseudonyms derived from a key stored in `<report>/keys/pseudonym.key`.
  Reusing the same output directory keeps pseudonyms stable across captures; deleting the key
  makes old pseudonyms unlinkable.
* Do not publish raw pcaps or logs.

## 9. Limitations

* Header-only capture shows destinations, timing and volumes, never content. Encrypted DNS
  (DoH) to an outside server is invisible to the lab resolver and appears only as HTTPS flows; the
  lab intercepts plain DNS and can block DNS over TLS (`BLOCK_DOT=1`).
* Lookups cached before the capture make some addresses look "contacted without a lookup".
* A box may behave differently on a lab network (for example when it sees no other devices), at
  other times, or after an update.
* The verdict policy is conservative: it misses behavior that no feed knows and that does not look
  like a timer, and it never says a device is clean.
* The detectors, the crowd-mixing simulator and the synthetic demo share their authors; synthetic
  results say nothing about real products.
