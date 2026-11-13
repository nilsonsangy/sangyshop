"""Lab auto-block Lambda (AWS).

Flow: CloudWatch alarm (login-failure brute force) -> EventBridge -> this function.
The function queries CloudWatch Logs Insights for failed logins per source IP,
decides which IPs to block with the pure function ``decide_block`` and creates
inbound ``deny`` entries (rule numbers 100-199) in the lab subnet NACL.

Design choices:
  * idempotent per IP: an IP that already has a deny entry never gets a second one;
  * private (RFC 1918), loopback and link-local ranges are never blocked;
  * the IAM role only allows the NACL entry APIs on the lab NACL ARN.

Environment variables (all set by deploy-blocker.ps1):
  NACL_ID          lab NACL id (required)
  LOG_GROUP        log group to query (required)
  TOPIC_ARN        SNS topic that receives failure notifications
  THRESHOLD        minimum failed logins per IP in the window (default 10)
  WINDOW_MINUTES   Logs Insights time window (default 5)
  EXTRA_PROTECTED_CIDRS  comma separated extra CIDRs that must never be blocked
"""

import ipaddress
import json
import os
import time
from collections.abc import Mapping

RULE_MIN = 100
RULE_MAX = 199
DEFAULT_THRESHOLD = 10
DEFAULT_WINDOW_MINUTES = 5

# RFC 1918 private ranges, loopback and link-local (never blocked).
DEFAULT_PROTECTED_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
)

INSIGHTS_QUERY = (
    'filter event = "auth_login" and result = "failure" '
    "| stats count(*) as failures by ip"
)


# --------------------------------------------------------------------------
# Pure decision logic (no AWS, no I/O)
# --------------------------------------------------------------------------

def _parse_ipv4(value):
    """Return an IPv4Address or None.

    Accepts plain IPv4 and IPv4-mapped IPv6 ("::ffff:1.2.3.4"), tolerating surrounding
    whitespace, "[...]" brackets and a "%zone" suffix. Other IPv6 and invalid text
    such as 'unknown' return None.
    """
    text = str(value).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    text = text.split("%", 1)[0].strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version == 6:
        return addr.ipv4_mapped  # None for plain IPv6
    return addr


def _to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _normalize_existing(existing_rules):
    """Return (used_numbers: set[int], blocked_networks: list[IPv4Network]).

    Accepted shapes for ``existing_rules``:
      * mapping {rule_number: cidr or None}
      * iterable of ints (rule numbers only)
      * iterable of dicts with RuleNumber and optional CidrBlock (NACL entry shape)
    Only entries inside 100-199 count as "already blocked"; every number is "used".
    """
    pairs = []
    if existing_rules is None:
        existing_rules = ()
    if isinstance(existing_rules, Mapping):
        pairs = [(_to_int(k), v) for k, v in existing_rules.items()]
    else:
        for item in existing_rules:
            if isinstance(item, Mapping):
                pairs.append((_to_int(item.get("RuleNumber")), item.get("CidrBlock")))
            else:
                pairs.append((_to_int(item), None))

    used = set()
    networks = []
    for number, cidr in pairs:
        if number is None:
            continue
        used.add(number)
        if cidr and RULE_MIN <= number <= RULE_MAX:
            try:
                networks.append(ipaddress.ip_network(str(cidr), strict=False))
            except ValueError:
                pass
    return used, networks


def decide_block(failures_by_ip, threshold=DEFAULT_THRESHOLD,
                 protected_cidrs=DEFAULT_PROTECTED_CIDRS, existing_rules=()):
    """Decide which IPs to block and which NACL rule number each one gets.

    Args:
        failures_by_ip: mapping IP -> number of failed logins (Logs Insights result).
        threshold: block IPs with count >= threshold.
        protected_cidrs: CIDRs that are never blocked (RFC 1918, loopback, link-local).
        existing_rules: NACL rule numbers already in use (see _normalize_existing).

    Returns a dict:
        block             {ip: rule_number}, rule numbers in 100-199, unused, ascending
        already_blocked   IPs at/above threshold that already have a deny entry (no duplicate)
        protected         IPs at/above threshold inside a protected range (ignored)
        below_threshold   valid IPs under the threshold
        invalid           entries that are not IPv4 addresses
        no_capacity       IPs that need a rule but 100-199 is full
    Deterministic: higher failure counts first, ties broken by IP.
    """
    protected = []
    for cidr in protected_cidrs or ():
        try:
            protected.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except ValueError:
            continue

    used, blocked_networks = _normalize_existing(existing_rules)
    free = [n for n in range(RULE_MIN, RULE_MAX + 1) if n not in used]

    result = {
        "block": {},
        "already_blocked": [],
        "protected": [],
        "below_threshold": [],
        "invalid": [],
        "no_capacity": [],
    }

    # Sum counts per address, so "x" and "::ffff:x" count as one IP.
    totals = {}
    for raw_ip, raw_count in (failures_by_ip or {}).items():
        addr = _parse_ipv4(raw_ip)
        count = _to_int(raw_count)
        if addr is None or count is None:
            result["invalid"].append(str(raw_ip))
            continue
        totals[addr] = totals.get(addr, 0) + count

    candidates = []
    for addr, count in totals.items():
        ip = str(addr)
        if count < threshold:
            result["below_threshold"].append(ip)
        elif any(addr in net for net in protected):
            result["protected"].append(ip)
        elif any(addr in net for net in blocked_networks):
            result["already_blocked"].append(ip)
        else:
            candidates.append((ip, count))

    candidates.sort(key=lambda item: (-item[1], int(ipaddress.ip_address(item[0]))))
    seen = set()
    for ip, _count in candidates:
        if ip in seen:  # same address written two ways in the input
            continue
        seen.add(ip)
        if free:
            result["block"][ip] = free.pop(0)
        else:
            result["no_capacity"].append(ip)
    return result


# --------------------------------------------------------------------------
# AWS plumbing (only runs inside Lambda)
# --------------------------------------------------------------------------

def _protected_cidrs():
    extra = [c.strip() for c in os.environ.get("EXTRA_PROTECTED_CIDRS", "").split(",") if c.strip()]
    return list(DEFAULT_PROTECTED_CIDRS) + extra


def _query_failures(logs, log_group, window_minutes):
    """Run the Logs Insights query and return {ip: failures}."""
    end = int(time.time())
    start = end - window_minutes * 60
    query_id = logs.start_query(
        logGroupName=log_group, startTime=start, endTime=end, queryString=INSIGHTS_QUERY
    )["queryId"]
    deadline = time.time() + 45
    while True:
        resp = logs.get_query_results(queryId=query_id)
        status = resp.get("status")
        if status == "Complete":
            break
        if status in ("Failed", "Cancelled", "Timeout"):
            raise RuntimeError("Logs Insights query ended with status %s" % status)
        if time.time() > deadline:
            raise RuntimeError("Logs Insights query did not finish in 45 seconds")
        time.sleep(1)

    failures = {}
    for row in resp.get("results", []):
        fields = {f["field"]: f["value"] for f in row}
        if "ip" in fields and "failures" in fields:
            failures[fields["ip"]] = fields["failures"]
    return failures


def _existing_ingress_rules(ec2, nacl_id):
    """Return {rule_number: cidr} for inbound entries of the NACL (the default rule 32767 included)."""
    acl = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]
    return {
        e["RuleNumber"]: e.get("CidrBlock")
        for e in acl.get("Entries", [])
        if not e.get("Egress", False)
    }


def _notify_failure(sns, topic_arn, message):
    if not topic_arn:
        return
    sns.publish(
        TopicArn=topic_arn,
        Subject="Lab: automatic block FAILED",
        Message=message + "\nApply the manual containment (add a NACL deny entry for the attacker IP).",
    )


def handler(event, context):
    """EventBridge entry point. Returns a small status dict (also logged as JSON)."""
    import boto3  # imported lazily so decide_block stays importable without boto3

    nacl_id = os.environ.get("NACL_ID", "")
    log_group = os.environ.get("LOG_GROUP", "")
    topic_arn = os.environ.get("TOPIC_ARN", "")
    threshold = int(os.environ.get("THRESHOLD", DEFAULT_THRESHOLD))
    window = int(os.environ.get("WINDOW_MINUTES", DEFAULT_WINDOW_MINUTES))

    ec2 = boto3.client("ec2")
    logs = boto3.client("logs")
    sns = boto3.client("sns")

    started = time.time()
    created, errors = {}, []
    decision = {}
    try:
        if not nacl_id:
            raise RuntimeError("NACL_ID is not configured")
        if not log_group:
            raise RuntimeError("LOG_GROUP is not configured")
        failures = _query_failures(logs, log_group, window)
        existing = _existing_ingress_rules(ec2, nacl_id)
        decision = decide_block(failures, threshold, _protected_cidrs(), existing)

        for ip, rule_number in decision["block"].items():
            try:
                ec2.create_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=rule_number,
                    Protocol="-1",
                    RuleAction="deny",
                    Egress=False,
                    CidrBlock="%s/32" % ip,
                )
                created[ip] = rule_number
            except Exception as exc:  # one failed IP must not stop the others
                errors.append("%s (rule %s): %s" % (ip, rule_number, exc))
        if decision.get("no_capacity"):
            errors.append("NACL rule range %d-%d is full; not blocked: %s"
                          % (RULE_MIN, RULE_MAX, ", ".join(decision["no_capacity"])))
    except Exception as exc:
        errors.append(str(exc))

    if errors:
        try:
            _notify_failure(sns, topic_arn, "Blocker errors on %s: %s" % (nacl_id, "; ".join(errors)))
        except Exception as exc:
            errors.append("SNS publish failed: %s" % exc)

    summary = {
        "status": "error" if errors else "ok",
        "blocked": created,
        "already_blocked": decision.get("already_blocked", []),
        "protected": decision.get("protected", []),
        "below_threshold": decision.get("below_threshold", []),
        "invalid": decision.get("invalid", []),
        "errors": errors,
        "elapsed_seconds": round(time.time() - started, 2),
    }
    print(json.dumps(summary))
    return summary
