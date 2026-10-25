# Outreach messages: first contact with operators

Replace the bracketed fields before sending. Keep claims to what is written here: lab
results are synthetic, and real numbers come from the customer's own pilot.

Sources for the facts used below:
- FBI public service announcement on BADBOX 2.0 (June 2025): more than 1 million infected
  consumer devices, used as residential proxies.

---

## 1. LinkedIn connection note (under 300 characters)

**FR**

> Bonjour [Prénom], je développe AEGIS, une solution qui aide les opérateurs à repérer les box Android TV pré-infectées (type BadBox) sur leur réseau, à partir des NetFlow/DNS existants, sans DPI. Votre avis de praticien m'intéresserait.

**EN**

> Hi [First name], I'm building AEGIS, which helps operators find pre-infected Android TV boxes (BadBox-type) on their network from existing NetFlow/DNS data, with no DPI. I'd value your perspective as a practitioner.

---

## 2. LinkedIn message after they accept

**FR**

> Merci pour la connexion, [Prénom].
>
> En juin 2025, le FBI a alerté sur BadBox 2.0 : plus d'un million de box TV et objets connectés infectés, souvent dès l'usine, et utilisés comme proxys résidentiels. Ces appareils sont chez les abonnés de tous les opérateurs, et les listes de blocage les détectent tard.
>
> AEGIS détecte ces campagnes à partir des données que vous avez déjà (NetFlow/IPFIX et logs DNS), sans DPI, sans rien installer chez les abonnés, hébergé chez vous. Chaque alerte est accompagnée de ses preuves, et rien n'est bloqué sans votre validation.
>
> Je propose un pilote de 4 semaines en lecture seule pour mesurer combien d'appareils compromis se trouvent sur votre réseau, avec un taux de fausses alertes que vous fixez à l'avance.
>
> Seriez-vous ouvert à un échange de 30 minutes avec une démo ?

**EN**

> Thanks for connecting, [First name].
>
> In June 2025 the FBI warned about BadBox 2.0: over a million TV boxes and connected devices infected, often from the factory, and used as residential proxies. These devices sit in every operator's subscriber base, and blocklists catch them late.
>
> AEGIS detects these campaigns from data you already have (NetFlow/IPFIX and DNS logs), with no DPI, nothing installed in homes, and hosted on your own infrastructure. Every alert comes with its evidence, and nothing is blocked without your approval.
>
> I'm offering a 4-week read-only pilot to measure how many compromised devices are on your network, with a false-alert budget you set in advance.
>
> Would you be open to a 30-minute call with a demo?

---

## 3. Email to a CISO / RSSI

**Subject (FR):** Box TV infectées sur votre réseau : pilote de mesure en 4 semaines

> Bonjour [Prénom],
>
> Je suis [Votre nom], fondateur d'AEGIS.
>
> Les box Android TV vendues à bas prix arrivent parfois infectées dès l'usine. En juin 2025, le FBI a signalé plus d'un million d'appareils compromis par BadBox 2.0, utilisés comme proxys pour de la fraude et des attaques. Pour un opérateur, cela signifie des adresses IP qui finissent sur des listes noires, des plaintes d'autres réseaux, et des abonnés qui ignorent tout.
>
> AEGIS repère ces campagnes à partir de vos NetFlow/IPFIX et logs DNS existants :
> - **Sans DPI** ni déchiffrement : métadonnées uniquement, abonnés pseudonymisés.
> - **Hébergé chez vous** (on-premise), conçu pour le RGPD et NIS2.
> - **Chaque alerte est prouvée :** sources indépendantes, explication, registre signé et infalsifiable.
> - **Aucun blocage sans votre accord :** simulation de l'impact, approbation signée, retour arrière immédiat.
>
> Je vous propose un **pilote de 4 semaines en mode observation**, sans aucune action sur votre réseau. Vous fixez à l'avance le taux de fausses alertes acceptable, et vous recevez un rapport sur votre propre trafic : appareils compromis détectés, ceux que vos outils actuels n'avaient pas vus, et le coût analyste par cas.
>
> Auriez-vous 30 minutes la semaine prochaine pour une démonstration ?
>
> Bien cordialement,
> [Votre nom]
> [Téléphone] · [Email]

**Subject (EN):** Infected TV boxes on your network: a 4-week measurement pilot

> Hi [First name],
>
> I'm [Your name], founder of AEGIS.
>
> Cheap Android TV boxes sometimes arrive infected from the factory. In June 2025 the FBI reported over a million devices compromised by BadBox 2.0 and used as proxies for fraud and attacks. For an operator, that means IP ranges ending up on blocklists, complaints from other networks, and subscribers who have no idea.
>
> AEGIS finds these campaigns from your existing NetFlow/IPFIX and DNS logs:
> - **No DPI** or decryption: metadata only, subscribers pseudonymized.
> - **Hosted on your infrastructure** (on-prem), designed for GDPR and NIS2.
> - **Every alert is backed by evidence:** independent sources, explanation, signed tamper-proof ledger.
> - **Nothing is blocked without your approval:** impact simulation, signed approval, instant rollback.
>
> I'm offering a **4-week shadow-mode pilot** with no action taken on your network. You set the acceptable false-alert rate in advance, and you get a report on your own traffic: compromised devices found, the ones your current tools missed, and analyst time per case.
>
> Would you have 30 minutes next week for a demo?
>
> Best regards,
> [Your name]
> [Phone] · [Email]

---

## 4. Email to an abuse desk / network security manager

**Subject (FR):** Moins de plaintes abuse liées aux box TV compromises

> Bonjour [Prénom],
>
> Votre équipe reçoit sans doute régulièrement des signalements d'abus (proxys, scans, DDoS) qui remontent à des abonnés dont un appareil est compromis, souvent une box Android TV bon marché.
>
> AEGIS identifie ces lignes **avant** que les plaintes n'arrivent, à partir de vos NetFlow et logs DNS, sans DPI. Il regroupe les abonnés touchés par une même campagne, fournit les preuves de chaque cas, et prépare la notification à l'abonné. Rien n'est bloqué automatiquement.
>
> Un pilote de 4 semaines en lecture seule permettrait de mesurer, sur votre réseau, combien de lignes sont concernées et combien de signalements auraient pu être anticipés.
>
> Seriez-vous disponible pour un échange de 30 minutes ?
>
> Cordialement,
> [Votre nom]

**Subject (EN):** Fewer abuse complaints from compromised TV boxes

> Hi [First name],
>
> Your team probably handles abuse reports (proxies, scans, DDoS) that trace back to subscribers with a compromised device, often a cheap Android TV box.
>
> AEGIS identifies those lines **before** the complaints arrive, from your NetFlow and DNS logs, with no DPI. It groups the subscribers hit by the same campaign, provides the evidence for each case, and prepares the subscriber notification. Nothing is blocked automatically.
>
> A 4-week read-only pilot would measure, on your own network, how many lines are affected and how many reports could have been anticipated.
>
> Would you be available for a 30-minute call?
>
> Best regards,
> [Your name]

---

## 5. Follow-up after 5–7 days without reply

**FR**

> Bonjour [Prénom], je me permets de relancer mon message de la semaine dernière. Si le sujet ne relève pas de votre périmètre, pourriez-vous m'indiquer la bonne personne ? Merci d'avance.

**EN**

> Hi [First name], following up on my message from last week. If this isn't in your area, could you point me to the right person? Thank you.

---

## What not to write

- No accuracy percentages, no "zero false positives", no "best on the market".
- No lab numbers presented as field results. If you mention them, say "in our lab benchmark (simulated network)".
- No naming of IPTV apps or box brands as malicious without published, verified evidence.
- No statement that AEGIS blocks pirate IPTV: that requires a court or Arcom order.
