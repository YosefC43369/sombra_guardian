"""
threat_actor_intelligence.ingestion.taxii_ingestor — TAXII 2.1 client.

A minimal TAXII 2.1 reader: it lists API roots → collections → pages of STIX
objects, and feeds each page to the ``STIXIngestor`` parser. TAXII envelopes are
STIX-object collections (``{"objects": [...], "more": bool, "next": "..."}``), so
parsing is delegated entirely to the STIX layer; this module only handles the
TAXII HTTP surface (Accept headers, pagination cursors, basic auth token).

The parse path is pure (feed it an envelope dict) so it is testable offline; the
network path (``run``) is guarded and paginates politely.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .base import BaseIngestor, IngestResult
from .stix_ingestor import STIXIngestor

TAXII_ACCEPT = "application/taxii+json;version=2.1"


class TAXIIIngestor(BaseIngestor):
    name = "taxii"
    source_class = "community"

    def __init__(self, *, provider_name: str = "taxii",
                 source_class: str = "community", max_pages: int = 20, **kw):
        super().__init__(**kw)
        self.provider_name = provider_name
        self.max_pages = max_pages
        self._stix = STIXIngestor(provider_name=provider_name,
                                  source_class=source_class, http=self.http)

    def parse(self, raw: Any, **kw) -> IngestResult:
        """Parse a single TAXII envelope (or a raw STIX bundle)."""
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        env = json.loads(raw) if isinstance(raw, str) else raw
        # A TAXII envelope has 'objects'; hand the whole thing to the STIX parser
        # which reads the same key.
        return self._stix.parse(env)

    def _auth_headers(self) -> Dict[str, str]:
        h = {"Accept": TAXII_ACCEPT}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def discover_collections(self, api_root: str, *, store=None
                             ) -> List[Dict[str, Any]]:  # pragma: no cover
        url = api_root.rstrip("/") + "/collections/"
        resp = self.http.get(url, headers=self._auth_headers())
        if resp.status != 200:
            return []
        try:
            return json.loads(resp.text).get("collections", [])
        except Exception:
            return []

    def run(self, *, api_root: str = "", collection_id: str = "",
            store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.provider_name)
        if not api_root:
            return result
        collections = ([{"id": collection_id}] if collection_id
                       else self.discover_collections(api_root, store=store))
        for coll in collections:
            cid = coll.get("id")
            if not cid:
                continue
            url = f"{api_root.rstrip('/')}/collections/{cid}/objects/"
            pages = 0
            while url and pages < self.max_pages:
                resp, _ = self.conditional_get(url, store=store,
                                               headers=self._auth_headers())
                if resp.not_modified:
                    result.not_modified = True
                    break
                if resp.status != 200:
                    result.errors.append(f"{url}: HTTP {resp.status}")
                    break
                try:
                    env = json.loads(resp.text)
                except Exception as exc:
                    result.errors.append(f"{url}: {exc}")
                    break
                result.extend(self._stix.parse(env))
                pages += 1
                nxt = env.get("next")
                url = (f"{api_root.rstrip('/')}/collections/{cid}/objects/"
                       f"?next={nxt}") if (env.get("more") and nxt) else ""
        return result


__all__ = ["TAXIIIngestor", "TAXII_ACCEPT"]
