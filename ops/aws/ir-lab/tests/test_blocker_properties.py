"""Property tests for the pure decision function of the auto-block Lambda.

Covers the blocking decision (decide_block): thresholds, protected ranges,
idempotence per IP and the NACL rule number range.

Run: uvx --with hypothesis pytest ops/aws/ir-lab/tests
"""

import importlib.util
import ipaddress
from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st

_LAMBDA = Path(__file__).resolve().parents[1] / "blocker" / "lambda_function.py"
_spec = importlib.util.spec_from_file_location("blocker_lambda_function", _LAMBDA)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

decide_block = _module.decide_block
DEFAULT_PROTECTED_CIDRS = _module.DEFAULT_PROTECTED_CIDRS
RULE_MIN = _module.RULE_MIN
RULE_MAX = _module.RULE_MAX

PBT_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)

# --------------------------------------------------------------------------
# Strategies
# --------------------------------------------------------------------------

# A mix of private/loopback/link-local addresses and public ones, so that the
# protected branch is exercised often.
_first_octet = st.sampled_from([8, 10, 45, 127, 169, 172, 192, 198, 203])
ipv4_text = st.one_of(
    st.builds(
        lambda a, b, c, d: "%d.%d.%d.%d" % (a, b, c, d),
        _first_octet,
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
    ),
    st.ip_addresses(v=4).map(str),
)

failures_by_ip = st.dictionaries(ipv4_text, st.integers(min_value=0, max_value=60), max_size=40)

thresholds = st.integers(min_value=1, max_value=40)


@st.composite
def protected_cidr_sets(draw):
    """Default protected ranges plus extra random CIDRs (sometimes replaced entirely)."""
    extra = draw(
        st.lists(
            st.builds(
                lambda ip, prefix: str(ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False)),
                ipv4_text,
                st.integers(min_value=8, max_value=32),
            ),
            max_size=4,
        )
    )
    base = draw(st.sampled_from([tuple(DEFAULT_PROTECTED_CIDRS), ()]))
    return list(base) + extra


@st.composite
def existing_rule_configs(draw):
    """{rule_number: cidr or None}; numbers inside and outside the reserved range."""
    numbers = draw(
        st.lists(
            st.one_of(st.integers(100, 199), st.integers(1, 99), st.integers(200, 400)),
            unique=True,
            max_size=60,
        )
    )
    rules = {}
    for number in numbers:
        cidr = draw(st.one_of(st.none(), ipv4_text.map(lambda ip: ip + "/32")))
        rules[number] = cidr
    return rules


def _in_any(ip, cidrs):
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)


# --------------------------------------------------------------------------
# Properties
# --------------------------------------------------------------------------

@PBT_SETTINGS
@given(failures_by_ip, thresholds, protected_cidr_sets(), existing_rule_configs())
def test_never_blocks_protected_ip(failures, threshold, protected, existing):
    decision = decide_block(failures, threshold, protected, existing)
    for ip in decision["block"]:
        assert not _in_any(ip, protected), "protected IP %s was blocked" % ip


@PBT_SETTINGS
@given(failures_by_ip, thresholds, protected_cidr_sets(), existing_rule_configs())
def test_rule_numbers_are_unique_reserved_and_unused(failures, threshold, protected, existing):
    decision = decide_block(failures, threshold, protected, existing)
    numbers = list(decision["block"].values())
    assert len(numbers) == len(set(numbers)), "duplicate rule number assigned"
    for number in numbers:
        assert RULE_MIN <= number <= RULE_MAX
        assert number not in existing, "rule number %s already exists" % number


@PBT_SETTINGS
@given(failures_by_ip, thresholds, protected_cidr_sets(), existing_rule_configs())
def test_only_ips_at_or_above_threshold_are_blocked(failures, threshold, protected, existing):
    decision = decide_block(failures, threshold, protected, existing)
    normalized = {str(ipaddress.ip_address(ip)): count for ip, count in failures.items()}
    for ip in decision["block"]:
        assert normalized[ip] >= threshold, "%s blocked with %s < %s" % (ip, normalized[ip], threshold)
    for ip in decision["below_threshold"]:
        assert ip not in decision["block"]


@PBT_SETTINGS
@given(failures_by_ip, thresholds, protected_cidr_sets(), existing_rule_configs())
def test_decision_is_idempotent(failures, threshold, protected, existing):
    first = decide_block(failures, threshold, protected, existing)

    # Apply the first decision: every blocked IP now has a /32 deny entry.
    applied = dict(existing)
    for ip, number in first["block"].items():
        applied[number] = ip + "/32"

    second = decide_block(failures, threshold, protected, applied)

    assert second["block"] == {} or set(second["block"]) <= set(first["no_capacity"]), (
        "second call re-blocked: %r" % (second["block"],)
    )
    for ip in first["block"]:
        assert ip in second["already_blocked"], "%s not reported as already_blocked" % ip
        assert ip not in second["block"]


# --------------------------------------------------------------------------
# IPv4-mapped IPv6 regression (the app logs "::ffff:a.b.c.d")
# --------------------------------------------------------------------------

public_ipv4 = st.ip_addresses(v=4).map(str).filter(
    lambda ip: not _in_any(ip, DEFAULT_PROTECTED_CIDRS)
)
private_ipv4 = st.sampled_from(["10.1.2.3", "172.16.5.9", "192.168.0.7", "127.0.0.1", "169.254.1.1"])
mapped_wrappers = st.sampled_from(["::ffff:%s", " ::ffff:%s ", "[::ffff:%s]", "::FFFF:%s"])


def test_real_world_mapped_ip_is_blocked():
    decision = decide_block({"::ffff:203.0.113.10": "20"}, 10, DEFAULT_PROTECTED_CIDRS, {})
    assert list(decision["block"]) == ["203.0.113.10"]
    assert decision["invalid"] == []


def test_plain_ipv6_is_still_invalid():
    decision = decide_block({"2001:db8::1": 50, "::1": 50, "unknown": 50}, 10, DEFAULT_PROTECTED_CIDRS, {})
    assert decision["block"] == {}
    assert sorted(decision["invalid"]) == ["2001:db8::1", "::1", "unknown"]


@PBT_SETTINGS
@given(public_ipv4, mapped_wrappers, st.integers(10, 60), thresholds)
def test_mapped_ipv6_at_threshold_is_blocked_as_plain_ipv4(ip, wrapper, extra, threshold):
    count = max(threshold, extra)
    decision = decide_block({wrapper % ip: count}, threshold, DEFAULT_PROTECTED_CIDRS, {})
    assert list(decision["block"]) == [ip]
    assert decision["invalid"] == []


@PBT_SETTINGS
@given(private_ipv4, mapped_wrappers, thresholds)
def test_mapped_form_of_protected_address_stays_protected(ip, wrapper, threshold):
    decision = decide_block({wrapper % ip: 1000}, threshold, DEFAULT_PROTECTED_CIDRS, {})
    assert decision["block"] == {}
    assert decision["protected"] == [ip]


@PBT_SETTINGS
@given(public_ipv4, st.integers(1, 30), st.integers(1, 30))
def test_mixed_forms_are_summed_per_address(ip, plain_count, mapped_count):
    threshold = plain_count + mapped_count
    failures = {ip: plain_count, "::ffff:" + ip: mapped_count}
    decision = decide_block(failures, threshold, DEFAULT_PROTECTED_CIDRS, {})
    assert list(decision["block"]) == [ip]
    # One count short of the sum: nothing is blocked.
    below = decide_block(failures, threshold + 1, DEFAULT_PROTECTED_CIDRS, {})
    assert below["block"] == {}
    assert below["below_threshold"] == [ip]
