# Architecture

## Vue d'ensemble

```
                         Internet
                            │
                      ┌─────▼─────┐   table d'entrée (edge association)
 Customer VPC         │    IGW    │   10.0.1.0/24 ──► GWLBe
 10.0.0.0/16          └─────┬─────┘
                            │
   Subnet public 10.0.0.0/24│   RT : 0.0.0.0/0 ──► IGW   |  local
        ┌───────────────────▼──────────┐
        │  GWLB Endpoint (GWLBe)       │◄──────────────┐
        └───────────────┬──────────────┘               │ livraison locale après inspection
                        │ PrivateLink                   │
   Subnet privé 10.0.1.0/24  RT : 0.0.0.0/0 ──► GWLBe   │
        ┌───────────────────────────────┐              │
        │ EC2 application (HTTP :80)    │──────────────┘ (trafic sortant → GWLBe)
        └───────────────────────────────┘
                        │
 ═══════════════════════╪═══════════════════════════════════════════
 Security Service VPC   │ 10.1.0.0/16
                 ┌──────▼──────┐  GENEVE / UDP 6081
                 │    GWLB     │  (subnet 10.1.1.0/24)
                 └──┬───────┬──┘
          ┌─────────▼──┐ ┌──▼─────────┐   subnet 10.1.0.0/24
          │ Appliance 1│ │ Appliance 2│   IPS GENEVE, health check TCP 8080
          └────────────┘ └────────────┘
```

## Les composants

- **Gateway Load Balancer** : load balancer de couche 3 « bump-in-the-wire ». Il encapsule chaque paquet en GENEVE
  et le distribue aux appliances par flux (hash 5-tuple, *flow stickiness*), dans les deux sens.
- **VPC Endpoint Service + GWLB Endpoint** : le service expose le GWLB par PrivateLink ; le GWLBe est le *next hop*
  placé dans les tables de routage du Customer VPC (`vpc_endpoint_id` dans `aws_route`).
- **Appliances** : reçoivent du GENEVE sur UDP 6081, décident (autoriser / abandonner), et répondent au GWLB.
  Les health checks du GWLB ne sont **pas** encapsulés (HTTP simple sur TCP 8080).

## Routage en détail

| Table | Association | Routes |
|---|---|---|
| `customer_edge` | **IGW** (`aws_route_table_association.gateway_id`) | `10.0.0.0/16 local`, `10.0.1.0/24 → GWLBe` |
| `customer_gwlbe` | subnet public | `10.0.0.0/16 local`, `0.0.0.0/0 → IGW` |
| `customer_app` | subnet privé | `10.0.0.0/16 local`, `0.0.0.0/0 → GWLBe` |
| `security_appliance` | subnet appliances | `10.1.0.0/16 local`, `0.0.0.0/0 → IGW` (SSM, paquets) |
| `security_gwlb` | subnet GWLB | `10.1.0.0/16 local` |

Règles à retenir :

- Après inspection, le trafic ressort du GWLBe et est routé par **la table du subnet du GWLBe** : c'est elle qui
  décide entre livraison locale (flux entrant) et sortie vers l'IGW (flux sortant).
- Le GWLBe et l'application doivent être dans **des subnets différents**.
- La table d'entrée de l'IGW ne contient que le CIDR du subnet applicatif : c'est ce qui force l'inspection du flux entrant.
- Le trafic des appliances elles-mêmes (SSM, mises à jour) sort par l'IGW du Security VPC et n'est **pas** inspecté.

## Flux détaillés

### Entrant (Internet → application)

```
Client ─► IGW ─(edge RT)─► GWLBe ─► GWLB ═GENEVE═► Appliance ─(allow)─► GWLB ─► GWLBe ─(local)─► App
                                                      └─(drop)─► ✗  (le paquet n'existe plus)
```

### Sortant / réponse (application → Internet)

```
App ─(0.0.0.0/0)─► GWLBe ─► GWLB ═GENEVE═► Appliance ─(allow)─► GWLB ─► GWLBe ─(0.0.0.0/0)─► IGW ─► Internet
```

Le hash symétrique du GWLB envoie aller et retour d'un même flux à la **même appliance**, qui garde donc son état
(ici : la liste des flux bloqués).

## Contrat GWLB ↔ appliance (GENEVE)

Paquet reçu : `IP(GWLB → appliance) / UDP(src éphémère, dst 6081) / GENEVE(+ TLV classe 0x0108) / paquet client`.

Pour **autoriser** un paquet, l'appliance renvoie le même datagramme au GWLB en respectant :

| Champ | Valeur du retour |
|---|---|
| IP source / destination (externes) | **inversées** (source = IP de l'appliance, destination = IP du GWLB) |
| Ports UDP (externes) | **conservés** : source = port utilisé par le GWLB, destination = 6081 — *pas* inversés |
| En-tête GENEVE et TLV (dont *flow cookie*, ID du GWLBe) | **inchangés** — un cookie manquant ou modifié fait abandonner le paquet |
| Checksum IP externe | recalculé |

Pour **bloquer**, l'appliance n'envoie simplement rien. Le GWLB ne génère aucun message d'erreur.

Autres contraintes : le GWLB ne fragmente pas et ne fait pas de PMTUD ; MTU de l'interface GWLB 8500 octets, l'encapsulation
ajoute 68 octets.

## Choix de conception

- **Une AZ, N appliances** : simple à lire ; les cibles doivent exister dans chaque AZ activée sur le GWLB.
- **SSM plutôt que SSH** : aucune clé, aucun port d'administration ouvert ; l'accès aux logs passe par Run Command.
- **IMDSv2 obligatoire** sur toutes les instances.
- **User-data compressé** (`base64gzip`) pour embarquer les scripts Python sans dépasser les 16 Ko, et
  `user_data_replace_on_change` pour que toute modification du script remplace l'instance.
- **Dépendances explicites** : l'application ne démarre qu'une fois le chemin d'inspection complet
  (routes, attachements de cibles, listener) en place, car sa route par défaut traverse le GWLB.
