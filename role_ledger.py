#!/usr/bin/env python3
"""role-ledger: rebuild who holds which OpenZeppelin AccessControl role from
RoleGranted / RoleRevoked / RoleAdminChanged logs, verify the result against
hasRole() / getRoleAdmin() / getRoleMember(), and flag risky setups.

Only JSON-RPC is used. Standard library only.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

USER_AGENT = "role-ledger/0.1 (+https://github.com)"

# ---------------------------------------------------------------------------
# keccak-256 (constants are derived from the spec, not copied from a table)
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1


def _rc_bit(t):
    """Bit t of the Keccak round-constant LFSR (polynomial x^8+x^6+x^5+x^4+1)."""
    if t % 255 == 0:
        return 1
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


def _round_constants():
    out = []
    for i in range(24):
        rc = 0
        for j in range(7):
            rc |= _rc_bit(j + 7 * i) << ((1 << j) - 1)
        out.append(rc)
    return out


def _rotation_offsets():
    rot = [0] * 25
    x, y = 1, 0
    for t in range(24):
        rot[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return rot


_RC = _round_constants()
_ROT = _rotation_offsets()


def _rotl(v, n):
    n %= 64
    if n == 0:
        return v
    return ((v << n) | (v >> (64 - n))) & _MASK64


def _keccak_f(a):
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], _ROT[x + 5 * y])
        a = [
            b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
            for i in range(25)
        ]
        a[0] ^= _RC[rnd]
    return a


def _sponge256(data, pad_byte):
    """Keccak sponge, rate 1088, 32-byte output. pad 0x01 = Keccak-256, 0x06 = SHA3-256."""
    rate = 136
    msg = bytearray(data)
    msg.append(pad_byte)
    while len(msg) % rate:
        msg.append(0x00)
    msg[-1] |= 0x80
    st = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        st = _keccak_f(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


def keccak256(data):
    return _sponge256(data, 0x01)


def keccak_hex(data):
    return "0x" + keccak256(data).hex()


def selector(signature):
    return "0x" + keccak256(signature.encode())[:4].hex()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOPIC_GRANTED = keccak_hex(b"RoleGranted(bytes32,address,address)")
TOPIC_REVOKED = keccak_hex(b"RoleRevoked(bytes32,address,address)")
TOPIC_ADMIN_CHANGED = keccak_hex(b"RoleAdminChanged(bytes32,bytes32,bytes32)")
SEL_HAS_ROLE = selector("hasRole(bytes32,address)")
SEL_GET_ROLE_ADMIN = selector("getRoleAdmin(bytes32)")
SEL_MEMBER_COUNT = selector("getRoleMemberCount(bytes32)")
SEL_MEMBER = selector("getRoleMember(bytes32,uint256)")

DEFAULT_ADMIN_ROLE = "0x" + "00" * 32

# Role names seen across common OpenZeppelin-based contracts. keccak256(name) == role id.
COMMON_ROLE_NAMES = [
    "MINTER_ROLE", "BURNER_ROLE", "PAUSER_ROLE", "UNPAUSER_ROLE", "UPGRADER_ROLE", "ADMIN_ROLE",
    "OPERATOR_ROLE", "MANAGER_ROLE", "GOVERNOR_ROLE", "GUARDIAN_ROLE", "EXECUTOR_ROLE",
    "PROPOSER_ROLE", "CANCELLER_ROLE", "TIMELOCK_ADMIN_ROLE", "RELAYER_ROLE", "BRIDGE_ROLE",
    "ORACLE_ROLE", "KEEPER_ROLE", "REBALANCER_ROLE", "STRATEGIST_ROLE", "HARVESTER_ROLE",
    "WHITELISTER_ROLE", "BLACKLISTER_ROLE", "SNAPSHOT_ROLE", "MAPPER_ROLE", "PREDICATE_ROLE",
    "DEPOSITOR_ROLE", "WITHDRAWER_ROLE", "VAULT_ROLE", "TREASURY_ROLE", "FEE_MANAGER_ROLE",
    "PAUSE_ROLE", "RESUME_ROLE", "FINALIZE_ROLE", "MANAGE_TOKEN_URI_ROLE", "CONFIG_ROLE",
    "DEPOSITS_ENABLER_ROLE", "DEPOSITS_DISABLER_ROLE", "WITHDRAWALS_ENABLER_ROLE",
    "WITHDRAWALS_DISABLER_ROLE", "BridgingManager.DEPOSITS_ENABLER_ROLE",
    "BridgingManager.DEPOSITS_DISABLER_ROLE", "BridgingManager.WITHDRAWALS_ENABLER_ROLE",
    "BridgingManager.WITHDRAWALS_DISABLER_ROLE", "STAKING_MODULE_PAUSE_ROLE",
    "STAKING_MODULE_RESUME_ROLE", "STAKING_MODULE_MANAGE_ROLE", "REPORT_EXITED_VALIDATORS_ROLE",
    "REPORT_REWARDS_MINTED_ROLE", "MANAGE_WITHDRAWAL_CREDENTIALS_ROLE", "MINTER", "BURNER",
    "PAUSER", "ADMIN", "OPERATOR", "OWNER_ROLE", "DEFAULT_ADMIN", "EMERGENCY_ROLE",
    "LIQUIDATOR_ROLE", "SETTER_ROLE", "VERIFIER_ROLE", "SIGNER_ROLE", "ISSUER_ROLE",
]


def build_name_map(extra_names=()):
    names = {DEFAULT_ADMIN_ROLE: "DEFAULT_ADMIN_ROLE"}
    for n in list(COMMON_ROLE_NAMES) + list(extra_names):
        names[keccak_hex(n.encode())] = n
    return names


# ---------------------------------------------------------------------------
# JSON-RPC
# ---------------------------------------------------------------------------

class RpcError(Exception):
    pass


class Rpc:
    def __init__(self, url, timeout=60, retries=3):
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.calls = 0
        self._id = 0

    def call(self, method, params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        )
        last = None
        for attempt in range(self.retries):
            try:
                self.calls += 1
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as exc:
                try:
                    payload = json.loads(exc.read().decode())
                except (ValueError, OSError):
                    payload = None
                if isinstance(payload, dict) and payload.get("error") and exc.code not in (429, 502, 503, 504):
                    break
                last = exc
                time.sleep(0.5 * (attempt + 1))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last = exc
                time.sleep(0.5 * (attempt + 1))
        else:
            raise RpcError("%s failed: %s" % (method, last))
        if "error" in payload and payload["error"]:
            raise RpcError("%s: %s" % (method, payload["error"].get("message", payload["error"])))
        return payload.get("result")


_RANGE_WORDS = ("range", "limit", "too many", "exceed", "block", "archive", "pruned", "result", "timeout", "large")


def looks_like_range_error(message):
    msg = message.lower()
    return any(w in msg for w in _RANGE_WORDS)


def fetch_logs(rpc, address, topics, from_block, to_block, chunk=None, max_requests=400):
    """Fetch logs, splitting the range when the node rejects it."""
    logs = []
    work = []
    if chunk:
        start = from_block
        while start <= to_block:
            end = min(start + chunk - 1, to_block)
            work.append((start, end))
            start = end + 1
        work.reverse()
    else:
        work.append((from_block, to_block))
    requests = 0
    while work:
        lo, hi = work.pop()
        if requests >= max_requests:
            raise RpcError("eth_getLogs needed more than %d requests; narrow --from-block or use --chunk" % max_requests)
        requests += 1
        try:
            part = rpc.call("eth_getLogs", [{
                "address": address, "fromBlock": hex(lo), "toBlock": hex(hi), "topics": [topics],
            }])
        except RpcError as exc:
            if lo == hi or not looks_like_range_error(str(exc)):
                raise
            mid = (lo + hi) // 2
            work.append((mid + 1, hi))
            work.append((lo, mid))
            continue
        logs.extend(part)
    return logs, requests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def norm_addr(a):
    return "0x" + a.lower().replace("0x", "").rjust(40, "0")[-40:]


def word_to_addr(word):
    return "0x" + word.replace("0x", "").rjust(64, "0")[-40:]


def norm_word(word):
    return "0x" + word.replace("0x", "").rjust(64, "0")[-64:].lower()


def to_int(h):
    return int(h, 16)


def code_kind(code):
    if not code or code == "0x":
        return "eoa"
    if code.lower().startswith("0xef0100"):
        return "eoa-7702"
    return "contract"


def encode_call(sel, *words):
    """ABI-encode a call with 32-byte word arguments (bytes32, address, uint256)."""
    out = sel
    for w in words:
        if isinstance(w, int):
            out += "%064x" % w
        else:
            out += norm_word(w)[2:]
    return out


# ---------------------------------------------------------------------------
# Core logic (pure functions, testable without network)
# ---------------------------------------------------------------------------

def parse_events(logs):
    events = []
    for lg in logs:
        if lg.get("removed"):
            continue
        t0 = lg["topics"][0].lower()
        ev = {
            "block": to_int(lg["blockNumber"]),
            "log_index": to_int(lg.get("logIndex", "0x0")),
            "tx": lg.get("transactionHash"),
        }
        topics = lg["topics"]
        if t0 == TOPIC_GRANTED or t0 == TOPIC_REVOKED:
            ev["kind"] = "granted" if t0 == TOPIC_GRANTED else "revoked"
            ev["role"] = norm_word(topics[1])
            ev["account"] = word_to_addr(topics[2])
            ev["sender"] = word_to_addr(topics[3])
        elif t0 == TOPIC_ADMIN_CHANGED:
            ev["kind"] = "admin_changed"
            ev["role"] = norm_word(topics[1])
            ev["previous_admin"] = norm_word(topics[2])
            ev["new_admin"] = norm_word(topics[3])
        else:
            continue
        events.append(ev)
    events.sort(key=lambda e: (e["block"], e["log_index"]))
    return events


def replay(events):
    """Replay events into the current role table.

    Returns dict role -> {holders: {account: info}, admin: role, grants: n, revokes: n,
                          former: {account: last_revoked_block}}
    """
    roles = {}

    def role_entry(r):
        if r not in roles:
            roles[r] = {"holders": {}, "admin": DEFAULT_ADMIN_ROLE, "grants": 0, "revokes": 0, "former": {}}
        return roles[r]

    for ev in events:
        if ev["kind"] == "admin_changed":
            role_entry(ev["role"])["admin"] = ev["new_admin"]
            role_entry(ev["new_admin"])
            continue
        entry = role_entry(ev["role"])
        acct = ev["account"]
        if ev["kind"] == "granted":
            entry["grants"] += 1
            if acct not in entry["holders"]:  # OZ does not emit on a no-op grant, but be safe
                entry["holders"][acct] = {
                    "granted_block": ev["block"], "granted_by": ev["sender"], "tx": ev["tx"],
                    "self_granted": ev["sender"] == acct,
                }
        else:
            entry["revokes"] += 1
            if acct in entry["holders"]:
                del entry["holders"][acct]
                entry["former"][acct] = ev["block"]
            else:
                entry["former"].setdefault(acct, ev["block"])
    return roles


def evaluate(roles, names, codes, verification=None):
    """Produce findings from the replayed table and optional on-chain verification.

    verification: dict role -> {"has_role": {account: bool|None}, "admin": role|None,
                                "members": [account] | None}
    """
    findings = []

    def add(level, code, msg):
        findings.append({"level": level, "code": code, "message": msg})

    def label(r):
        return names.get(r, "unknown role %s" % r)

    verification = verification or {}

    # on-chain cross-check
    for r, entry in roles.items():
        v = verification.get(r)
        if not v:
            continue
        for acct, ok in v.get("has_role", {}).items():
            if ok is False:
                add("WARN", "HASROLE_MISMATCH", "%s: logs say %s holds it but hasRole() returns false (role changed without an event, or the scan range is incomplete)" % (label(r), acct))
        if v.get("admin") is not None and v["admin"] != entry["admin"]:
            add("WARN", "ROLE_ADMIN_MISMATCH", "%s: getRoleAdmin() is %s but logs say %s" % (label(r), label(v["admin"]), label(entry["admin"])))
        if v.get("members") is not None:
            extra = sorted(set(v["members"]) - set(entry["holders"]))
            missing = sorted(set(entry["holders"]) - set(v["members"]))
            for a in extra:
                add("WARN", "ENUMERABLE_EXTRA_HOLDER", "%s: getRoleMember() lists %s but no RoleGranted log was found for it" % (label(r), a))
            for a in missing:
                add("WARN", "ENUMERABLE_MISSING_HOLDER", "%s: logs say %s holds it but getRoleMember() does not list it" % (label(r), a))
            if not extra and not missing:
                add("OK", "ENUMERABLE_MATCHES", "%s: getRoleMember() set equals the %d holder(s) rebuilt from logs" % (label(r), len(entry["holders"])))

    checked = [ok for v in verification.values() for ok in v.get("has_role", {}).values() if ok is not None]
    if checked and all(checked):
        add("OK", "HASROLE_CONFIRMED", "hasRole() confirms all %d holder(s) rebuilt from logs" % len(checked))
    admins_checked = [r for r, v in verification.items() if v.get("admin") is not None]
    if admins_checked and all(verification[r]["admin"] == roles[r]["admin"] for r in admins_checked):
        add("OK", "ROLE_ADMIN_CONFIRMED", "getRoleAdmin() agrees with the logs for all %d role(s)" % len(admins_checked))

    # admin structure
    admin_roles = {entry["admin"] for entry in roles.values()}
    default_holders = roles.get(DEFAULT_ADMIN_ROLE, {}).get("holders", {})
    if DEFAULT_ADMIN_ROLE in roles or any(a == DEFAULT_ADMIN_ROLE for a in admin_roles):
        if not default_holders:
            add("WARN", "NO_DEFAULT_ADMIN", "DEFAULT_ADMIN_ROLE has no holder; roles administered by it can never be granted or revoked again")
        elif len(default_holders) == 1:
            only = next(iter(default_holders))
            add("INFO", "SINGLE_DEFAULT_ADMIN", "DEFAULT_ADMIN_ROLE has exactly one holder: %s (%s)" % (only, codes.get(only, "?")))
    for r in sorted(admin_roles):
        for acct in roles.get(r, {}).get("holders", {}):
            kind = codes.get(acct)
            if kind in ("eoa", "eoa-7702"):
                governed = sorted(label(x) for x, e in roles.items() if e["admin"] == r)
                add("WARN", "ADMIN_HOLDER_IS_EOA", "%s is held by %s, an externally owned account (%s); it administers: %s" % (label(r), acct, kind, ", ".join(governed)))
    for r, entry in roles.items():
        admin = entry["admin"]
        admin_holders = roles.get(admin, {}).get("holders", {})
        if not admin_holders and (entry["holders"] or entry["grants"]):
            if admin != DEFAULT_ADMIN_ROLE or DEFAULT_ADMIN_ROLE in roles:
                add("WARN", "ROLE_ORPHANED", "%s: its admin role %s has no holder, so its member list is frozen" % (label(r), label(admin)))
        if not entry["holders"] and entry["grants"]:
            add("INFO", "ROLE_EMPTY", "%s: every holder was revoked (last at block %d)" % (label(r), max(entry["former"].values())))
        for acct, info in entry["holders"].items():
            if info["self_granted"] and r != DEFAULT_ADMIN_ROLE:
                add("INFO", "SELF_GRANT", "%s: %s granted the role to itself at block %d" % (label(r), acct, info["granted_block"]))
        if r not in names:
            add("INFO", "UNKNOWN_ROLE_NAME", "role %s is not in the name list; pass --role-name NAME if you know it" % r)
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def verify_on_chain(rpc, contract, roles):
    """Call hasRole / getRoleAdmin / getRoleMember* for every rebuilt role."""
    out = {}
    for r, entry in roles.items():
        v = {"has_role": {}, "admin": None, "members": None}
        for acct in entry["holders"]:
            try:
                res = rpc.call("eth_call", [{"to": contract, "data": encode_call(SEL_HAS_ROLE, r, acct)}, "latest"])
                v["has_role"][acct] = bool(int(res, 16)) if res and res != "0x" else None
            except RpcError:
                v["has_role"][acct] = None
        try:
            res = rpc.call("eth_call", [{"to": contract, "data": encode_call(SEL_GET_ROLE_ADMIN, r)}, "latest"])
            v["admin"] = norm_word(res) if res and len(res) >= 66 else None
        except RpcError:
            v["admin"] = None
        try:
            res = rpc.call("eth_call", [{"to": contract, "data": encode_call(SEL_MEMBER_COUNT, r)}, "latest"])
            count = int(res, 16) if res and res != "0x" else None
        except RpcError:
            count = None
        if count is not None and count <= 500:
            members = []
            for i in range(count):
                res = rpc.call("eth_call", [{"to": contract, "data": encode_call(SEL_MEMBER, r, i)}, "latest"])
                members.append(word_to_addr(res[:66]))
            v["members"] = members
        out[r] = v
    return out


def run(rpc, contract, from_block=0, to_block=None, chunk=None, extra_names=(), verify=True):
    contract = norm_addr(contract)
    names = build_name_map(extra_names)
    chain_id = to_int(rpc.call("eth_chainId", []))
    head = to_int(rpc.call("eth_blockNumber", []))
    if to_block is None:
        to_block = head
    logs, requests = fetch_logs(rpc, contract, [TOPIC_GRANTED, TOPIC_REVOKED, TOPIC_ADMIN_CHANGED],
                                from_block, to_block, chunk=chunk)
    events = parse_events(logs)
    roles = replay(events)
    addrs = set()
    for entry in roles.values():
        addrs.update(entry["holders"].keys())
    codes = {a: code_kind(rpc.call("eth_getCode", [a, "latest"])) for a in sorted(addrs)}
    verification = verify_on_chain(rpc, contract, roles) if verify else {}
    findings = evaluate(roles, names, codes, verification)
    return {
        "contract": contract,
        "chain_id": chain_id,
        "scan": {"from_block": from_block, "to_block": to_block, "events": len(events), "log_requests": requests,
                 "granted": sum(1 for e in events if e["kind"] == "granted"),
                 "revoked": sum(1 for e in events if e["kind"] == "revoked"),
                 "admin_changed": sum(1 for e in events if e["kind"] == "admin_changed")},
        "names": {r: names[r] for r in roles if r in names},
        "roles": roles,
        "codes": codes,
        "verification": verification,
        "events": events,
        "findings": findings,
    }


def render(result):
    out = []
    names = result["names"]
    codes = result["codes"]
    ver = result["verification"]
    sc = result["scan"]
    out.append("contract: %s  chain id: %d" % (result["contract"], result["chain_id"]))
    out.append("logs: blocks %d..%d, %d events (granted %d, revoked %d, admin changed %d), %d eth_getLogs request(s)" % (
        sc["from_block"], sc["to_block"], sc["events"], sc["granted"], sc["revoked"], sc["admin_changed"], sc["log_requests"]))
    out.append("")
    out.append("roles:")
    if not result["roles"]:
        out.append("  (no AccessControl events in range)")
    ordered = sorted(result["roles"].items(), key=lambda kv: (kv[0] != DEFAULT_ADMIN_ROLE, names.get(kv[0], "~" + kv[0])))
    for r, entry in ordered:
        name = names.get(r, "unknown role")
        admin_name = names.get(entry["admin"], entry["admin"])
        v = ver.get(r, {})
        enum = ""
        if v.get("members") is not None:
            enum = ", getRoleMemberCount %d" % len(v["members"])
        out.append("  %s  %s" % (name, r))
        out.append("    admin role: %s  holders: %d  (grants %d, revokes %d%s)" % (
            admin_name, len(entry["holders"]), entry["grants"], entry["revokes"], enum))
        for acct, info in sorted(entry["holders"].items(), key=lambda kv: kv[1]["granted_block"]):
            check = v.get("has_role", {}).get(acct)
            check_s = "" if check is None else ("  hasRole: %s" % ("true" if check else "FALSE"))
            out.append("    - %s  %-9s granted at block %d by %s%s" % (
                acct, codes.get(acct, "?"), info["granted_block"], info["granted_by"], check_s))
        for acct, blk in sorted(entry["former"].items(), key=lambda kv: kv[1]):
            if acct not in entry["holders"]:
                out.append("    - %s  (revoked at block %d)" % (acct, blk))
    out.append("")
    out.append("checks:")
    if not result["findings"]:
        out.append("  (nothing to report)")
    for f in result["findings"]:
        out.append("  %-4s %-26s %s" % (f["level"], f["code"], f["message"]))
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="Rebuild AccessControl role holders from logs, verify them on chain, and flag risky setups.")
    p.add_argument("--rpc", required=True, help="JSON-RPC endpoint URL")
    p.add_argument("--contract", required=True, help="AccessControl contract address")
    p.add_argument("--from-block", type=int, default=0, help="first block to scan (default 0)")
    p.add_argument("--to-block", type=int, default=None, help="last block to scan (default latest)")
    p.add_argument("--chunk", type=int, default=None, help="fixed eth_getLogs block range per request (default: whole range, split on error)")
    p.add_argument("--role-name", action="append", default=[], help="extra role name to resolve (keccak256 of the string); repeatable")
    p.add_argument("--no-verify", action="store_true", help="skip hasRole / getRoleAdmin / getRoleMember calls")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = p.parse_args(argv)

    rpc = Rpc(args.rpc)
    try:
        result = run(rpc, args.contract, args.from_block, args.to_block, args.chunk, args.role_name, not args.no_verify)
    except RpcError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))
    return 1 if any(f["level"] == "WARN" for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
