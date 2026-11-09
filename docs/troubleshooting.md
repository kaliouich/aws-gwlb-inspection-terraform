# Dépannage

## Symptôme : cibles GWLB « healthy » mais aucun trafic ne passe

C'est le piège le plus courant avec une appliance GENEVE maison. Les health checks ne sont **pas** encapsulés : ils
réussissent même si le chemin de données GENEVE est cassé.

### Cause rencontrée sur ce projet

La première version de l'appliance renvoyait les paquets avec un socket UDP classique lié au port 6081, donc avec les
ports **inversés** (source 6081 → port éphémère du GWLB). AWS exige de **conserver** les ports UDP externes
(source = port du GWLB, destination = 6081). Le GWLB abandonnait alors toutes les réponses, sans aucune erreur :

- connexions entrantes : SYN reçu et réfléchi par l'appliance, jamais de SYN-ACK ;
- connexions sortantes de l'application : même chose, plus d'accès SSM ni Internet.

**Correctif** : construire l'en-tête UDP à la main et l'envoyer sur un socket brut (`socket.SOCK_RAW`, nécessite root),
voir `send_back()` dans [templates/ips.py](../templates/ips.py).

### Méthode de diagnostic (dichotomie)

1. **Les cibles sont-elles saines ?** `aws elbv2 describe-target-health` — nécessaire mais pas suffisant.
2. **Le GENEVE arrive-t-il aux appliances ?** Capture via SSM :
   ```bash
   tcpdump -nn -v -i ens5 udp port 6081
   ```
   Il faut voir le paquet client **décodé** (`Geneve ... options [class Unknown (0x108) ...]`). Ici les paquets arrivaient
   et repartaient, mais rien ne revenait en face : le problème était donc **après** l'appliance.
3. **Éliminer les NACL** : ajouter une règle `allow all` temporaire (entrant) sur les deux NACL. Sans effet ici → pas les NACL.
4. **Contourner le GWLB pour valider le reste** : route de l'app `0.0.0.0/0 → IGW` et suppression de la route d'entrée
   de l'IGW. L'application répondait → instance, Security Group et EIP corrects.
5. **Tester un seul sens** : remettre la route d'entrée vers le GWLBe en laissant la sortie directe par l'IGW. Échec →
   le paquet réfléchi par l'appliance n'est jamais livré : c'est bien le **format du retour GENEVE**.
6. Relire les exigences de retour (ports conservés, TLV intacts, checksum IP) et corriger.

Toute modification manuelle faite pendant le diagnostic doit être annulée ; `terraform plan` doit ensuite afficher « No changes ».

## Autres points de vigilance

| Problème | Explication / solution |
|---|---|
| L'app est injoignable alors que les routes semblent bonnes | Vérifier qu'une route d'entrée **sur l'IGW** (edge association) pointe le CIDR du subnet applicatif vers le GWLBe. |
| L'instance applicative n'apparaît pas dans SSM | Son seul accès sortant passe par l'inspection : si le chemin GWLB est cassé, SSM l'est aussi. |
| `terraform apply` échoue à créer l'endpoint | Le GWLB endpoint met ~2 min à devenir `available` ; les routes qui le ciblent attendent cet état. |
| Le client voit un timeout, pas un 403 | Comportement normal d'un blocage par abandon de paquet. |
| Une attaque est bloquée avec une étiquette inattendue | Première signature qui correspond : `/etc/passwd` (sid 1000010) est évaluée avant Shellshock et l'injection de commande. |
| Analyse refusée (`tiros:CreateQuery`) | VPC Reachability Analyzer nécessite des droits IAM supplémentaires ; utiliser `tcpdump` + dichotomie. |
| Un scanner Internet apparaît dans les logs de l'app | Normal : une EIP ouverte sur `0.0.0.0/0` est sondée en quelques minutes. Restreindre `app_allowed_cidrs`. |

## Commandes utiles

```bash
# État des cibles
aws elbv2 describe-target-health --target-group-arn "$(terraform output -raw target_group_arn)"

# Alertes et compteurs d'une appliance (via SSM)
aws ssm send-command --instance-ids <id> --document-name AWS-RunShellScript \
  --parameters 'commands=["tail -20 /var/log/gwlb-ips/eve.json","curl -s localhost:8080/stats"]'

# Journal d'accès de l'application
aws ssm send-command --instance-ids "$(terraform output -raw app_instance_id)" \
  --document-name AWS-RunShellScript --parameters 'commands=["tail -20 /var/log/app/access.log"]'
```
