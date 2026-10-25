# AEGIS OMEGA SHIELD

**Repérez les équipements compromis sur votre réseau, avec des preuves opposables.**

Des boîtiers TV et objets connectés vendus déjà infectés transforment les foyers de vos abonnés en nœuds de
botnet et en proxys résidentiels loués. Vous collectez déjà la télémétrie qui les révèle. SHIELD la
transforme en détections que votre SOC peut vérifier, sans soupçonner le foyer qui regarde simplement
beaucoup de vidéo.

## Ce que fait SHIELD

* **Détecte** les balises C2 périodiques, le trafic de proxy résidentiel, les requêtes DGA et les rafales de
  bots DDoS à partir de vos flux NetFlow/IPFIX, journaux DNS des résolveurs, Zeek ou télémétrie des box.
* **Explique** chaque alerte : éléments de preuve et leurs empreintes, nombre de sources indépendantes
  concordantes, hypothèses bénignes examinées, et ce que le système savait au moment de la décision.
* **S'abstient** quand les données sont insuffisantes, au lieu de deviner. La marque, le type d'équipement,
  l'usage d'applications IPTV ou la géographie ne sont jamais des preuves.
* **Protège votre réseau de votre propre réaction :** avant tout blocage, il simule l'impact sur
  l'hébergement mutualisé et les CDN et refuse quand l'impact est inconnu. Rien ne s'exécute sans votre
  politique signée, une référence de validation juridique et l'approbation d'une seconde personne.
* **Démontre sa valeur :** un rapport de preuve de valeur avec les fausses alertes pour 10 000 jours-équipement,
  l'effort analyste par dossier, le délai de détection, le coût par équipement protégé et par mois, et une
  attestation d'absence de blocage.

## Conçu pour les opérateurs

| | |
|---|---|
| Déploiement | Dans vos locaux ou sur un cloud souverain : un conteneur et PostgreSQL. Aucune donnée ne quitte votre réseau dans la configuration par défaut. |
| Vie privée | Métadonnées de flux et DNS uniquement. Pas de contenu, pas de déchiffrement, pas d'URL. Identifiants abonnés pseudonymisés dès l'ingestion ; la ré-identification reste dans vos systèmes. |
| Intégration | Envoi de fichiers en HTTPS (NetFlow/IPFIX en CSV via nfdump ou pmacct, journaux Zeek, journaux JSON des résolveurs, agents de box) ; identités et rôles issus de votre fournisseur OIDC (Keycloak, Entra ID) ; Prometheus et Grafana. |
| Traçabilité | Journal d'audit signé et chaîné ; séparation des rôles et double validation ; versions signées avec SBOM. |
| IA | Optionnelle et consultative. La détection et toutes les décisions fonctionnent sans elle. |
| Conformité | Modèles d'AIPD et de cartographie des données pour votre DPO ; architecture de sécurité et modèle de menaces reliés aux tests automatisés. Aucune certification revendiquée pour la v1. |

## Commencez par un pilote payant en mode observation

Deux à quatre semaines, en lecture seule, sur la télémétrie dont vous disposez déjà. Critères de succès
définis ensemble avant le démarrage. À la fin : le rapport de preuve de valeur sur votre réseau, et une
décision fondée sur vos chiffres.

**Contact :** [À COMPLÉTER PAR LE FONDATEUR : nom, e-mail, téléphone]

*SHIELD v1 est commercialisé en mode observation (aucun blocage). Les résultats obtenus sur notre
laboratoire synthétique ne sont pas des résultats terrain ; la performance réelle est mesurée pendant votre
pilote.*
