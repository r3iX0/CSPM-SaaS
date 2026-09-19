"""Where an asset runs, spelled one way (DECISIONS.md §113).

The SQL expression and the Python function are two spellings of one rule: the
dashboard's region map groups with the first, and the asset list filters a
linked code through the second. Pure tests. No database.
"""

import pytest
from sqlalchemy.dialects import postgresql

from app.services.placement import REGION, region_key


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("westeurope", "westeurope"),
        ("West Europe", "westeurope"),
        ("East US 2", "eastus2"),
        ("us-east-1", "us-east-1"),
        ("global", None),
        ("Global", None),
        ("", None),
        (None, None),
    ],
)
def test_a_region_has_one_spelling(value: str | None, expected: str | None) -> None:
    assert region_key(value) == expected


def test_the_sql_spelling_folds_global_and_empty_into_null() -> None:
    sql = str(
        REGION.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    )
    assert sql == "nullif(nullif(lower(replace(cloud_resources.region, ' ', '')), 'global'), '')"
