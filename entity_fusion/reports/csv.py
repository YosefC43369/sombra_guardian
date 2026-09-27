"""entity_fusion.reports.csv — flatten resolved identities to CSV for
spreadsheets / SIEM ingestion. One row per identity; multi-valued fields are
pipe-joined. Uses ``csv`` + ``io`` (stdlib) so quoting is always correct."""

from __future__ import annotations

import csv as _csv
import io
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..orchestrator import FusionResult
    from ..identity import Identity

_COLUMNS = ["id", "label", "primary_type", "band", "score", "record_count",
            "providers", "aliases", "emails", "usernames", "domains", "phones",
            "wallets", "websites"]


def _row(ident: "Identity") -> dict:
    v = ident.values_by_type
    return {
        "id": ident.id,
        "label": ident.label,
        "primary_type": ident.primary_type.value,
        "band": ident.band,
        "score": f"{ident.score:.0f}",
        "record_count": len(ident.member_ids),
        "providers": "|".join(ident.providers),
        "aliases": "|".join(ident.aliases),
        "emails": "|".join(v.get("email", [])),
        "usernames": "|".join(v.get("username", [])),
        "domains": "|".join(v.get("domain", []) + v.get("subdomain", [])),
        "phones": "|".join(v.get("phone", [])),
        "wallets": "|".join(v.get("wallet", [])),
        "websites": "|".join(v.get("website", [])),
    }


def render_identities(identities: "List[Identity]") -> str:
    buf = io.StringIO()
    writer = _csv.DictWriter(buf, fieldnames=_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for ident in identities:
        writer.writerow(_row(ident))
    return buf.getvalue()


def render(result: "FusionResult") -> str:
    return render_identities(result.identities)
