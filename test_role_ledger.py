import hashlib
import unittest

import role_ledger as m

T_GRANT = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
T_REVOKE = "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"
T_ADMIN = "0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff"

DEFAULT = "0x" + "00" * 32
PAUSE_ROLE = "0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d"
RESUME_ROLE = "0x2fc10cc8ae19568712f7a176fb4978616a610650813c9d05326c34abb62749c7"
OP_DEPOSITS_ENABLER = "0x4b43b36766bde12c5e9cbbc37d15f8d1f769f08f54720ab370faeb4ce893753a"

# Ethereum mainnet, Lido WithdrawalQueueERC721 0x889e...f9b1 (AccessControlEnumerable).
# Subset of the real logs (one grant/revoke pair of PAUSE_ROLE left out).
WQ = "0x889edc2edab5f40e902b864ad4d7ade8e412f9b1"
DEPLOYER = "0xa818ff9ec93122bf9401ab4340c42de638cd600a"
AGENT = "0x3e40d73eb977dc6a537af587d48316fee66e9c8c"
GATE_SEAL_1 = "0x1ad5cb2955940f998081c1ef5f5f00875431aa90"
GATE_SEAL_2 = "0x79243345edbe01a7e42edff5900156700d22611c"
PAUSER_A = "0x7914b5a1539b97bd0bbd155757f25fd79a522d24"
PAUSER_B = "0x6019cb557978296ba3c08a7b73225c0975dfb2f7"
PAUSER_OLD = "0x8a854c4e750cdf24f138f34a9061b2f556066912"


def w(addr):
    return "0x" + addr[2:].rjust(64, "0")


def log(block, idx, topics, tx="0xtx"):
    return {"blockNumber": hex(block), "logIndex": hex(idx), "topics": topics,
            "data": "0x", "transactionHash": tx, "removed": False}


INIT_TX = "0x592d68a259af899fb435da0ac08c2fd500cb423f37f1d8ce8e3120cb84186b21"
WQ_LOGS = [
    log(17266004, 59, [T_GRANT, DEFAULT, w(DEPLOYER), w(DEPLOYER)], INIT_TX),
    log(17266004, 61, [T_GRANT, PAUSE_ROLE, w(GATE_SEAL_1), w(DEPLOYER)], INIT_TX),
    log(17266004, 64, [T_GRANT, RESUME_ROLE, w(DEPLOYER), w(DEPLOYER)], INIT_TX),
    log(17266004, 66, [T_REVOKE, RESUME_ROLE, w(DEPLOYER), w(DEPLOYER)], INIT_TX),
    log(17266004, 122, [T_GRANT, DEFAULT, w(AGENT), w(DEPLOYER)], INIT_TX),
    log(17266004, 123, [T_REVOKE, DEFAULT, w(DEPLOYER), w(DEPLOYER)], INIT_TX),
    log(19740274, 0, [T_GRANT, PAUSE_ROLE, w(GATE_SEAL_2), w(AGENT)]),
    log(19740274, 1, [T_REVOKE, PAUSE_ROLE, w(GATE_SEAL_1), w(AGENT)]),
    log(22095872, 0, [T_REVOKE, PAUSE_ROLE, w(GATE_SEAL_2), w(AGENT)]),
    log(22817714, 0, [T_GRANT, PAUSE_ROLE, w(PAUSER_A), w(AGENT)]),
    log(22817714, 1, [T_GRANT, RESUME_ROLE, w(PAUSER_A), w(AGENT)]),
    log(23491115, 0, [T_GRANT, PAUSE_ROLE, w(PAUSER_OLD), w(AGENT)]),
    log(25402340, 0, [T_REVOKE, PAUSE_ROLE, w(PAUSER_OLD), w(AGENT)]),
    log(25402340, 1, [T_GRANT, PAUSE_ROLE, w(PAUSER_B), w(AGENT)]),
]
# Live state observed at block 26166104: holders per role (getRoleMember) and hasRole == true
WQ_MEMBERS = {
    DEFAULT: [AGENT],
    PAUSE_ROLE: [PAUSER_A, PAUSER_B],
    RESUME_ROLE: [PAUSER_A],
}

# OP Mainnet, Lido L2ERC20TokenBridge 0x8e01...6957 (plain AccessControl, namespaced role names)
OP_BRIDGE = "0x8e01013243a96601a86eb3153f0d9fa4fbfb6957"
OP_DEPLOYER = "0x2c01f405e3c525c0cb867789aaf077f3553ccbb7"
OP_EXECUTOR = "0xefa0db536d2c8089685630fafe88cf7805966fc3"
OP_LOGS = [
    log(17831155, 0, [T_GRANT, DEFAULT, w(OP_DEPLOYER), w(OP_DEPLOYER)]),
    log(17832728, 0, [T_GRANT, OP_DEPOSITS_ENABLER, w(OP_DEPLOYER), w(OP_DEPLOYER)]),
    log(17832764, 0, [T_GRANT, OP_DEPOSITS_ENABLER, w(OP_EXECUTOR), w(OP_DEPLOYER)]),
    log(17833018, 0, [T_REVOKE, OP_DEPOSITS_ENABLER, w(OP_DEPLOYER), w(OP_DEPLOYER)]),
    log(17833084, 0, [T_GRANT, DEFAULT, w(OP_EXECUTOR), w(OP_DEPLOYER)]),
    log(17833109, 0, [T_REVOKE, DEFAULT, w(OP_DEPLOYER), w(OP_DEPLOYER)]),
]


class FakeRpc:
    """Answers JSON-RPC from fixed data. members=None means getRoleMember* reverts."""

    def __init__(self, chain_id, head, logs, members, codes, has_role=None, role_admin=None, max_range=None):
        self.chain_id, self.head, self.logs, self.members, self.codes = chain_id, head, logs, members, codes
        self.has_role = has_role
        self.role_admin = role_admin or {}
        self.max_range = max_range
        self.calls = []

    def call(self, method, params):
        self.calls.append(method)
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getCode":
            return self.codes.get(params[0], "0x")
        if method == "eth_getLogs":
            f = params[0]
            lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
            if self.max_range and hi - lo + 1 > self.max_range:
                raise m.RpcError("block range too large")
            return [l for l in self.logs if lo <= int(l["blockNumber"], 16) <= hi]
        if method == "eth_call":
            data = params[0]["data"]
            sel, args = data[:10], data[10:]
            role = "0x" + args[:64]
            if sel == m.SEL_HAS_ROLE:
                acct = "0x" + args[64 + 24:128]
                if self.has_role is not None:
                    return "0x" + "%064x" % int(self.has_role(role, acct))
                return "0x" + "%064x" % int(acct in (self.members or {}).get(role, []))
            if sel == m.SEL_GET_ROLE_ADMIN:
                return self.role_admin.get(role, DEFAULT)
            if self.members is None:
                raise m.RpcError("execution reverted")
            if sel == m.SEL_MEMBER_COUNT:
                return "0x" + "%064x" % len(self.members.get(role, []))
            if sel == m.SEL_MEMBER:
                return w(self.members[role][int(args[64:128], 16)])
        raise AssertionError(method)


class KeccakTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(m.keccak_hex(b""), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_topics_and_selectors(self):
        self.assertEqual(m.TOPIC_GRANTED, T_GRANT)
        self.assertEqual(m.TOPIC_REVOKED, T_REVOKE)
        self.assertEqual(m.TOPIC_ADMIN_CHANGED, T_ADMIN)
        self.assertEqual(m.SEL_HAS_ROLE, "0x91d14854")
        self.assertEqual(m.SEL_GET_ROLE_ADMIN, "0x248a9ca3")
        self.assertEqual(m.SEL_MEMBER_COUNT, "0xca15c873")
        self.assertEqual(m.SEL_MEMBER, "0x9010d07c")

    def test_role_names(self):
        names = m.build_name_map()
        self.assertEqual(names[PAUSE_ROLE], "PAUSE_ROLE")
        self.assertEqual(names[RESUME_ROLE], "RESUME_ROLE")
        self.assertEqual(names[OP_DEPOSITS_ENABLER], "BridgingManager.DEPOSITS_ENABLER_ROLE")
        self.assertEqual(names[DEFAULT], "DEFAULT_ADMIN_ROLE")
        custom = m.build_name_map(["MY_ROLE"])
        self.assertEqual(custom[m.keccak_hex(b"MY_ROLE")], "MY_ROLE")

    def test_permutation_against_sha3(self):
        for n in (0, 1, 135, 136, 137, 271, 272, 500):
            data = (bytes(range(256)) * 2)[:n]
            self.assertEqual(m._sponge256(data, 0x06), hashlib.sha3_256(data).digest(), n)

    def test_constants_are_complete(self):
        self.assertEqual(len(m._RC), 24)
        self.assertEqual(m._RC[0], 1)
        self.assertEqual(m._RC[23], 0x8000000080008008)
        self.assertEqual(sorted(m._ROT), sorted([0] + [((t + 1) * (t + 2) // 2) % 64 for t in range(24)]))


class ReplayTests(unittest.TestCase):
    def test_withdrawal_queue(self):
        roles = m.replay(m.parse_events(WQ_LOGS))
        self.assertEqual(set(roles[DEFAULT]["holders"]), {AGENT})
        self.assertEqual(roles[DEFAULT]["former"][DEPLOYER], 17266004)
        self.assertEqual(set(roles[PAUSE_ROLE]["holders"]), {PAUSER_A, PAUSER_B})
        self.assertEqual(roles[PAUSE_ROLE]["holders"][PAUSER_B]["granted_by"], AGENT)
        self.assertEqual(roles[PAUSE_ROLE]["grants"], 5)
        self.assertEqual(roles[PAUSE_ROLE]["revokes"], 3)
        self.assertEqual(set(roles[RESUME_ROLE]["holders"]), {PAUSER_A})
        for r, members in WQ_MEMBERS.items():
            self.assertEqual(set(roles[r]["holders"]), set(members))

    def test_order_within_block(self):
        # grant then revoke in the same block must leave no holder
        logs = [log(5, 3, [T_REVOKE, RESUME_ROLE, w(DEPLOYER), w(DEPLOYER)]),
                log(5, 2, [T_GRANT, RESUME_ROLE, w(DEPLOYER), w(DEPLOYER)])]
        roles = m.replay(m.parse_events(logs))
        self.assertEqual(roles[RESUME_ROLE]["holders"], {})

    def test_role_admin_changed(self):
        logs = [log(1, 0, [T_ADMIN, PAUSE_ROLE, DEFAULT, RESUME_ROLE])]
        roles = m.replay(m.parse_events(logs))
        self.assertEqual(roles[PAUSE_ROLE]["admin"], RESUME_ROLE)
        self.assertIn(RESUME_ROLE, roles)

    def test_encode_call(self):
        data = m.encode_call(m.SEL_HAS_ROLE, PAUSE_ROLE, PAUSER_A)
        self.assertEqual(len(data), 10 + 128)
        self.assertEqual(data[:10], "0x91d14854")
        self.assertTrue(data.endswith(PAUSER_A[2:]))
        self.assertEqual(m.encode_call(m.SEL_MEMBER, DEFAULT, 7)[-1:], "7")


class RunTests(unittest.TestCase):
    def codes_of(self, res):
        return {f["code"] for f in res["findings"]}

    def test_withdrawal_queue_run(self):
        codes = {a: "0x60" for a in (AGENT, PAUSER_A, PAUSER_B)}
        rpc = FakeRpc(1, 26166104, WQ_LOGS, WQ_MEMBERS, codes)
        res = m.run(rpc, WQ)
        found = self.codes_of(res)
        self.assertIn("HASROLE_CONFIRMED", found)
        self.assertIn("ROLE_ADMIN_CONFIRMED", found)
        self.assertIn("ENUMERABLE_MATCHES", found)
        self.assertIn("SINGLE_DEFAULT_ADMIN", found)
        self.assertNotIn("ADMIN_HOLDER_IS_EOA", found)
        self.assertNotIn("HASROLE_MISMATCH", found)
        self.assertEqual(res["names"][PAUSE_ROLE], "PAUSE_ROLE")
        text = m.render(res)
        self.assertIn("PAUSE_ROLE", text)
        self.assertIn("hasRole: true", text)
        self.assertIn("(revoked at block 22095872)", text)

    def test_op_bridge_run_non_enumerable(self):
        codes = {OP_EXECUTOR: "0x60"}
        rpc = FakeRpc(10, 158042782, OP_LOGS, None, codes,
                      has_role=lambda r, a: a == OP_EXECUTOR)
        res = m.run(rpc, OP_BRIDGE)
        found = self.codes_of(res)
        self.assertIn("HASROLE_CONFIRMED", found)
        self.assertNotIn("ENUMERABLE_MATCHES", found)
        self.assertEqual(set(res["roles"][OP_DEPOSITS_ENABLER]["holders"]), {OP_EXECUTOR})
        self.assertEqual(res["scan"]["granted"], 4)

    def test_eoa_admin_and_mismatch(self):
        eoa = "0x" + "aa" * 20
        logs = [log(1, 0, [T_GRANT, DEFAULT, w(eoa), w(eoa)]),
                log(2, 0, [T_GRANT, PAUSE_ROLE, w(PAUSER_A), w(eoa)])]
        rpc = FakeRpc(1, 10, logs, None, {PAUSER_A: "0x60"}, has_role=lambda r, a: a == eoa)
        res = m.run(rpc, WQ)
        found = self.codes_of(res)
        self.assertIn("ADMIN_HOLDER_IS_EOA", found)
        self.assertIn("HASROLE_MISMATCH", found)
        self.assertNotIn("HASROLE_CONFIRMED", found)
        self.assertEqual(m.main.__name__, "main")

    def test_orphaned_and_no_default_admin(self):
        logs = [log(1, 0, [T_GRANT, DEFAULT, w(DEPLOYER), w(DEPLOYER)]),
                log(1, 1, [T_GRANT, PAUSE_ROLE, w(PAUSER_A), w(DEPLOYER)]),
                log(2, 0, [T_REVOKE, DEFAULT, w(DEPLOYER), w(DEPLOYER)])]
        rpc = FakeRpc(1, 10, logs, None, {PAUSER_A: "0x60"})
        res = m.run(rpc, WQ, verify=False)
        found = self.codes_of(res)
        self.assertIn("NO_DEFAULT_ADMIN", found)
        self.assertIn("ROLE_ORPHANED", found)
        self.assertIn("ROLE_EMPTY", found)
        self.assertNotIn("eth_call", rpc.calls)

    def test_enumerable_extra_holder_and_admin_mismatch(self):
        logs = [log(1, 0, [T_GRANT, PAUSE_ROLE, w(PAUSER_A), w(AGENT)])]
        rpc = FakeRpc(1, 10, logs, {PAUSE_ROLE: [PAUSER_A, PAUSER_B]}, {PAUSER_A: "0x60"},
                      role_admin={PAUSE_ROLE: RESUME_ROLE})
        res = m.run(rpc, WQ)
        found = self.codes_of(res)
        self.assertIn("ENUMERABLE_EXTRA_HOLDER", found)
        self.assertIn("ROLE_ADMIN_MISMATCH", found)

    def test_log_range_splitting(self):
        rpc = FakeRpc(1, 26166104, WQ_LOGS, None, {}, max_range=5_000_000)
        logs, requests = m.fetch_logs(rpc, WQ, [T_GRANT, T_REVOKE], 0, 26166104)
        self.assertEqual(len(logs), len(WQ_LOGS))
        self.assertGreater(requests, 5)
        with self.assertRaises(m.RpcError):
            m.fetch_logs(rpc, WQ, [T_GRANT], 0, 26166104, max_requests=2)
        self.assertTrue(m.looks_like_range_error("query returned more than 10000 results"))
        self.assertFalse(m.looks_like_range_error("invalid argument 0"))


if __name__ == "__main__":
    unittest.main()
