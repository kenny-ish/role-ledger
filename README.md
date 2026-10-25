# role-ledger

Rebuilds who holds which OpenZeppelin `AccessControl` role on a contract from its
`RoleGranted`, `RoleRevoked` and `RoleAdminChanged` logs, resolves the `bytes32` role ids
back to names, verifies the result against `hasRole()`, `getRoleAdmin()` and
`getRoleMember()` on the live contract, and flags setups where an EOA administers roles,
no one holds `DEFAULT_ADMIN_ROLE`, or a role can never be changed again. It talks to a
JSON-RPC node only and uses the Python standard library only.

## Example

Lido's WithdrawalQueue on Ethereum mainnet (AccessControlEnumerable):

```
$ python role_ledger.py --rpc https://mainnet.gateway.tenderly.co --contract 0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1
contract: 0x889edc2edab5f40e902b864ad4d7ade8e412f9b1  chain id: 1
logs: blocks 0..26166116, 20 events (granted 13, revoked 7, admin changed 0), 1 eth_getLogs request(s)

roles:
  DEFAULT_ADMIN_ROLE  0x0000000000000000000000000000000000000000000000000000000000000000
    admin role: DEFAULT_ADMIN_ROLE  holders: 1  (grants 2, revokes 1, getRoleMemberCount 1)
    - 0x3e40d73eb977dc6a537af587d48316fee66e9c8c  contract  granted at block 17266004 by 0xa818ff9ec93122bf9401ab4340c42de638cd600a  hasRole: true
    - 0xa818ff9ec93122bf9401ab4340c42de638cd600a  (revoked at block 17266004)
  FINALIZE_ROLE  0x485191a2ef18512555bd4426d18a716ce8e98c80ec2de16394dcf86d7d91bc80
    admin role: DEFAULT_ADMIN_ROLE  holders: 1  (grants 1, revokes 0, getRoleMemberCount 1)
    - 0xae7ab96520de3a18e5e111b5eaab095312d7fe84  contract  granted at block 17266004 by 0xa818ff9ec93122bf9401ab4340c42de638cd600a  hasRole: true
  MANAGE_TOKEN_URI_ROLE  0xbe882725f03f148e7c5a5e63ec45f182f7dcdb6bb8b92311ade5a6d138e0ee0f
    admin role: DEFAULT_ADMIN_ROLE  holders: 0  (grants 1, revokes 1, getRoleMemberCount 0)
    - 0x2e59a20f205bb85a89c53f1936454680651e618e  (revoked at block 17266004)
  ORACLE_ROLE  0x68e79a7bf1e0bc45d0a330c573bc367f9cf464fd326078812f301165fbda4ef1
    admin role: DEFAULT_ADMIN_ROLE  holders: 1  (grants 1, revokes 0, getRoleMemberCount 1)
    - 0x852ded011285fe67063a08005c71a85690503cee  contract  granted at block 17266004 by 0xa818ff9ec93122bf9401ab4340c42de638cd600a  hasRole: true
  PAUSE_ROLE  0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d
    admin role: DEFAULT_ADMIN_ROLE  holders: 2  (grants 6, revokes 4, getRoleMemberCount 2)
    - 0x7914b5a1539b97bd0bbd155757f25fd79a522d24  contract  granted at block 22817714 by 0x3e40d73eb977dc6a537af587d48316fee66e9c8c  hasRole: true
    - 0x6019cb557978296ba3c08a7b73225c0975dfb2f7  contract  granted at block 25402340 by 0x3e40d73eb977dc6a537af587d48316fee66e9c8c  hasRole: true
    - 0x1ad5cb2955940f998081c1ef5f5f00875431aa90  (revoked at block 19740274)
    - 0x79243345edbe01a7e42edff5900156700d22611c  (revoked at block 22095872)
    - 0xf9c9fdb4a5d2aa1d836d5370ab9b28bc1847e178  (revoked at block 23491115)
    - 0x8a854c4e750cdf24f138f34a9061b2f556066912  (revoked at block 25402340)
  RESUME_ROLE  0x2fc10cc8ae19568712f7a176fb4978616a610650813c9d05326c34abb62749c7
    admin role: DEFAULT_ADMIN_ROLE  holders: 1  (grants 2, revokes 1, getRoleMemberCount 1)
    - 0x7914b5a1539b97bd0bbd155757f25fd79a522d24  contract  granted at block 22817714 by 0x3e40d73eb977dc6a537af587d48316fee66e9c8c  hasRole: true
    - 0xa818ff9ec93122bf9401ab4340c42de638cd600a  (revoked at block 17266004)

checks:
  OK   ENUMERABLE_MATCHES         DEFAULT_ADMIN_ROLE: getRoleMember() set equals the 1 holder(s) rebuilt from logs
  OK   ENUMERABLE_MATCHES         PAUSE_ROLE: getRoleMember() set equals the 2 holder(s) rebuilt from logs
  OK   ENUMERABLE_MATCHES         FINALIZE_ROLE: getRoleMember() set equals the 1 holder(s) rebuilt from logs
  OK   ENUMERABLE_MATCHES         ORACLE_ROLE: getRoleMember() set equals the 1 holder(s) rebuilt from logs
  OK   ENUMERABLE_MATCHES         RESUME_ROLE: getRoleMember() set equals the 1 holder(s) rebuilt from logs
  OK   ENUMERABLE_MATCHES         MANAGE_TOKEN_URI_ROLE: getRoleMember() set equals the 0 holder(s) rebuilt from logs
  OK   HASROLE_CONFIRMED          hasRole() confirms all 6 holder(s) rebuilt from logs
  OK   ROLE_ADMIN_CONFIRMED       getRoleAdmin() agrees with the logs for all 6 role(s)
  INFO SINGLE_DEFAULT_ADMIN       DEFAULT_ADMIN_ROLE has exactly one holder: 0x3e40d73eb977dc6a537af587d48316fee66e9c8c (contract)
  INFO ROLE_EMPTY                 MANAGE_TOKEN_URI_ROLE: every holder was revoked (last at block 17266004)
```

Lido's L2 token bridge on OP Mainnet (plain AccessControl, so `getRoleMember` is not
available and only `hasRole` / `getRoleAdmin` are checked; role names are namespaced):

```
$ python role_ledger.py --rpc https://mainnet.optimism.io --contract 0x8E01013243a96601a86eb3153F0d9Fa4fbFb6957
contract: 0x8e01013243a96601a86eb3153f0d9fa4fbfb6957  chain id: 10
logs: blocks 0..158042846, 13 events (granted 10, revoked 3, admin changed 0), 1 eth_getLogs request(s)

roles:
  DEFAULT_ADMIN_ROLE  0x0000000000000000000000000000000000000000000000000000000000000000
    admin role: DEFAULT_ADMIN_ROLE  holders: 1  (grants 2, revokes 1)
    - 0xefa0db536d2c8089685630fafe88cf7805966fc3  contract  granted at block 17833084 by 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  hasRole: true
    - 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  (revoked at block 17833109)
  BridgingManager.DEPOSITS_DISABLER_ROLE  0x63f736f21cb2943826cd50b191eb054ebbea670e4e962d0527611f830cd399d6
    admin role: DEFAULT_ADMIN_ROLE  holders: 2  (grants 2, revokes 0)
    - 0xefa0db536d2c8089685630fafe88cf7805966fc3  contract  granted at block 17832800 by 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  hasRole: true
    - 0x4cf8fe0a4c2539f7efdd2047d8a5d46f14613088  contract  granted at block 17832821 by 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  hasRole: true
  BridgingManager.DEPOSITS_ENABLER_ROLE  0x4b43b36766bde12c5e9cbbc37d15f8d1f769f08f54720ab370faeb4ce893753a
    admin role: DEFAULT_ADMIN_ROLE  holders: 1  (grants 2, revokes 1)
    - 0xefa0db536d2c8089685630fafe88cf7805966fc3  contract  granted at block 17832764 by 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  hasRole: true
    - 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  (revoked at block 17833018)
  BridgingManager.WITHDRAWALS_DISABLER_ROLE  0x94a954c0bc99227eddbc0715a62a7e1056ed8784cd719c2303b685683908857c
    admin role: DEFAULT_ADMIN_ROLE  holders: 2  (grants 2, revokes 0)
    - 0xefa0db536d2c8089685630fafe88cf7805966fc3  contract  granted at block 17832911 by 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  hasRole: true
    - 0x4cf8fe0a4c2539f7efdd2047d8a5d46f14613088  contract  granted at block 17832939 by 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  hasRole: true
  BridgingManager.WITHDRAWALS_ENABLER_ROLE  0x9ab8816a3dc0b3849ec1ac00483f6ec815b07eee2fd766a353311c823ad59d0d
    admin role: DEFAULT_ADMIN_ROLE  holders: 1  (grants 2, revokes 1)
    - 0xefa0db536d2c8089685630fafe88cf7805966fc3  contract  granted at block 17832883 by 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  hasRole: true
    - 0x2c01f405e3c525c0cb867789aaf077f3553ccbb7  (revoked at block 17833066)

checks:
  OK   HASROLE_CONFIRMED          hasRole() confirms all 7 holder(s) rebuilt from logs
  OK   ROLE_ADMIN_CONFIRMED       getRoleAdmin() agrees with the logs for all 5 role(s)
  INFO SINGLE_DEFAULT_ADMIN       DEFAULT_ADMIN_ROLE has exactly one holder: 0xefa0db536d2c8089685630fafe88cf7805966fc3 (contract)
```

The exit code is 1 when at least one `WARN` finding exists, 0 otherwise, 2 on RPC failure.

## Usage

```
python role_ledger.py --rpc URL --contract ADDRESS [options]

  --rpc URL            JSON-RPC endpoint (required)
  --contract ADDRESS   AccessControl contract address (required)
  --from-block N       first block to scan (default 0)
  --to-block N         last block to scan (default latest)
  --chunk N            fixed block range per eth_getLogs request
                       (default: ask for the whole range and split in half when the node refuses)
  --role-name NAME     extra role name to resolve (keccak256 of the string); repeatable
  --no-verify          skip the hasRole / getRoleAdmin / getRoleMember calls
  --json               print the full result (roles, events, verification, findings) as JSON
```

Findings:

| code | level | meaning |
|---|---|---|
| `HASROLE_MISMATCH` | WARN | logs say an account holds a role but `hasRole()` says no |
| `ENUMERABLE_EXTRA_HOLDER` / `ENUMERABLE_MISSING_HOLDER` | WARN | `getRoleMember()` and the logs disagree |
| `ROLE_ADMIN_MISMATCH` | WARN | `getRoleAdmin()` differs from the replayed `RoleAdminChanged` history |
| `ADMIN_HOLDER_IS_EOA` | WARN | a role that administers other roles is held by an EOA (or an EIP-7702 delegated key) |
| `NO_DEFAULT_ADMIN` | WARN | nobody holds `DEFAULT_ADMIN_ROLE`; roles under it are frozen |
| `ROLE_ORPHANED` | WARN | a role whose admin role has no holder |
| `SINGLE_DEFAULT_ADMIN`, `ROLE_EMPTY`, `SELF_GRANT`, `UNKNOWN_ROLE_NAME` | INFO | worth a look, not necessarily wrong |

## How it works

1. Fetches every `RoleGranted(bytes32,address,address)`, `RoleRevoked(...)` and
   `RoleAdminChanged(bytes32,bytes32,bytes32)` log for the contract (all arguments are
   indexed, so everything is read from topics) and replays them in block / log-index order.
   The result is, per role: current holders with the block and sender of their grant,
   former holders with the block they were revoked, and the admin role.
2. Resolves role ids with a list of common names (`MINTER_ROLE`, `PAUSE_ROLE`,
   `BridgingManager.DEPOSITS_ENABLER_ROLE`, ...) plus any `--role-name` you pass;
   `keccak256(name)` must equal the role id.
3. Calls `hasRole(role, account)` for every rebuilt holder and `getRoleAdmin(role)` for every
   role. If the contract is `AccessControlEnumerable`, `getRoleMemberCount` / `getRoleMember`
   are read too and the two sets are compared, which catches roles changed without events
   (for example by an upgrade or a custom `_grantRole` path).
4. Classifies every current holder with `eth_getCode` so EOA-controlled admin roles stand out.

Event topics, function selectors and role ids are computed with a built-in keccak-256 whose
round constants and rotation offsets are generated from the Keccak specification at import
time.

## Tests

`python -m unittest -v`
