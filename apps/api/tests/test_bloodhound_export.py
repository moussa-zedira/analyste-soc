"""Tests : BloodHound JSON exporter (CE schema v5)."""

from __future__ import annotations

from apps.api.pentest.post_exploit.bloodhound_export import (
    BH_VERSION,
    BHComputer,
    BHDomain,
    BHGroup,
    BHUser,
    BloodHoundExportRequest,
    build_bloodhound_export,
)

DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"


def _sample_request() -> BloodHoundExportRequest:
    return BloodHoundExportRequest(
        domain=BHDomain(sid=DOMAIN_SID, name="EXAMPLE.LOCAL"),
        users=[
            BHUser(
                sid=f"{DOMAIN_SID}-1001",
                name="ALICE@EXAMPLE.LOCAL",
                domain="EXAMPLE.LOCAL",
                spn=["MSSQLSvc/db01.example.local:1433"],
                admin_count=True,
            ),
            BHUser(
                sid=f"{DOMAIN_SID}-1002",
                name="BOB@EXAMPLE.LOCAL",
                domain="EXAMPLE.LOCAL",
                asrep_roastable=True,
            ),
        ],
        computers=[
            BHComputer(
                sid=f"{DOMAIN_SID}-1101",
                name="DC01.EXAMPLE.LOCAL",
                domain="EXAMPLE.LOCAL",
                operating_system="Windows Server 2019",
                local_admins=[f"{DOMAIN_SID}-1001"],
            ),
        ],
        groups=[
            BHGroup(
                sid="S-1-5-32-544",
                name="ADMINISTRATORS@EXAMPLE.LOCAL",
                domain="EXAMPLE.LOCAL",
                members=[{"ObjectIdentifier": f"{DOMAIN_SID}-1001", "ObjectType": "User"}],
            ),
        ],
    )


def test_build_emits_4_collections():
    bundle = build_bloodhound_export(_sample_request())
    assert set(bundle.keys()) == {"users", "computers", "groups", "domains"}


def test_collections_have_meta_with_correct_count():
    bundle = build_bloodhound_export(_sample_request())
    assert bundle["users"]["meta"]["count"] == 2
    assert bundle["computers"]["meta"]["count"] == 1
    assert bundle["groups"]["meta"]["count"] == 1
    assert bundle["domains"]["meta"]["count"] == 1


def test_meta_uses_current_schema_version():
    bundle = build_bloodhound_export(_sample_request())
    for col in bundle.values():
        assert col["meta"]["version"] == BH_VERSION


def test_user_kerberoastable_has_hasspn_true():
    bundle = build_bloodhound_export(_sample_request())
    alice = bundle["users"]["data"][0]
    assert alice["Properties"]["hasspn"] is True
    assert alice["Properties"]["serviceprincipalnames"] == ["MSSQLSvc/db01.example.local:1433"]
    assert alice["Properties"]["admincount"] is True


def test_user_asrep_roastable_has_dontreqpreauth():
    bundle = build_bloodhound_export(_sample_request())
    bob = bundle["users"]["data"][1]
    assert bob["Properties"]["dontreqpreauth"] is True
    assert bob["Properties"]["hasspn"] is False


def test_computer_local_admins_emitted():
    bundle = build_bloodhound_export(_sample_request())
    dc = bundle["computers"]["data"][0]
    admins = dc["LocalAdmins"]["Results"]
    assert len(admins) == 1
    assert admins[0]["ObjectIdentifier"] == f"{DOMAIN_SID}-1001"
    assert admins[0]["ObjectType"] == "User"


def test_group_members_passed_through():
    bundle = build_bloodhound_export(_sample_request())
    g = bundle["groups"]["data"][0]
    assert g["Members"][0]["ObjectIdentifier"] == f"{DOMAIN_SID}-1001"


def test_domain_uppercased_and_includes_sid():
    bundle = build_bloodhound_export(_sample_request())
    d = bundle["domains"]["data"][0]
    assert d["ObjectIdentifier"] == DOMAIN_SID
    assert d["Properties"]["name"] == "EXAMPLE.LOCAL"
    assert d["Properties"]["domainsid"] == DOMAIN_SID


def test_object_identifier_matches_sid():
    bundle = build_bloodhound_export(_sample_request())
    assert bundle["users"]["data"][0]["ObjectIdentifier"] == f"{DOMAIN_SID}-1001"
    assert bundle["computers"]["data"][0]["ObjectIdentifier"] == f"{DOMAIN_SID}-1101"


def test_empty_lists_emit_empty_collections():
    req = BloodHoundExportRequest(domain=BHDomain(sid=DOMAIN_SID, name="X"))
    bundle = build_bloodhound_export(req)
    assert bundle["users"]["data"] == []
    assert bundle["computers"]["data"] == []
    assert bundle["groups"]["data"] == []
    assert bundle["users"]["meta"]["count"] == 0


def test_aces_passed_through_on_user():
    ace = {"PrincipalSID": "S-1-5-32-544", "PrincipalType": "Group", "RightName": "Owns", "IsInherited": False}
    req = BloodHoundExportRequest(
        domain=BHDomain(sid=DOMAIN_SID, name="X"),
        users=[BHUser(sid=f"{DOMAIN_SID}-1", name="A", domain="X", aces=[ace])],
    )
    bundle = build_bloodhound_export(req)
    assert bundle["users"]["data"][0]["Aces"] == [ace]


def test_computer_unconstrained_delegation_flag():
    req = BloodHoundExportRequest(
        domain=BHDomain(sid=DOMAIN_SID, name="X"),
        computers=[BHComputer(
            sid=f"{DOMAIN_SID}-1", name="DC", domain="X",
            unconstrained_delegation=True, has_laps=True,
        )],
    )
    bundle = build_bloodhound_export(req)
    props = bundle["computers"]["data"][0]["Properties"]
    assert props["unconstraineddelegation"] is True
    assert props["haslaps"] is True
