"""Where a dashboard risk's graph opens (DECISIONS.md §139)."""

from uuid import uuid4

from app.services.dashboard import route_ends, single_asset


def test_a_risk_on_one_asset_opens_on_that_asset() -> None:
    asset = uuid4()
    assert single_asset({asset}) == str(asset)


def test_a_risk_across_several_assets_opens_on_none_of_them() -> None:
    # Picking the worst would present one asset as though it were the risk.
    assert single_asset({uuid4(), uuid4()}) is None


def test_a_risk_on_no_asset_opens_on_none() -> None:
    assert single_asset(set()) is None


def test_a_route_is_named_by_where_it_starts_and_ends() -> None:
    path = [
        {"source_id": "/vm/web", "relationship": "has_identity", "target_id": "/mi/web"},
        {"source_id": "/mi/web", "relationship": "has_role_on", "target_id": "/kv/secrets"},
    ]
    assert route_ends(path) == {"entry_id": "/vm/web", "target_id": "/kv/secrets"}


def test_an_empty_or_malformed_route_is_named_by_nothing() -> None:
    assert route_ends([]) is None
    assert route_ends([{"source_id": "/vm/web"}]) is None
