"""Tests for entity_fusion.reports and entity_fusion.history — rendering a
FusionResult in every format and building a timeline."""

import json
import pytest

from entity_fusion.orchestrator import FusionEngine
from entity_fusion.authorization import AuthorizationContext
from entity_fusion import reports
from entity_fusion.entity import Entity, EntityType
from entity_fusion.history import HistoryEngine, ChangeKind

DEV = AuthorizationContext(dev_unsafe_allow_all=True)


def _result():
    records = [
        {"type": "username", "value": "John.Doe", "source": "s1",
         "display_name": "John Doe"},
        {"type": "username", "value": "johndoe", "source": "s2",
         "display_name": "John Doe"},
        {"type": "domain", "value": "example.com", "source": "s3"},
    ]
    return FusionEngine().fuse(records, ctx=DEV)


class TestReports:
    def test_json_is_valid(self):
        out = reports.render(_result(), "json")
        data = json.loads(out)
        assert "identities" in data and "stats" in data

    def test_markdown_has_sections(self):
        md = reports.render(_result(), "markdown")
        assert "# Entity Fusion Dossier" in md
        assert "## Confidence Matrix" in md
        assert "authorized investigation" in md.lower()

    def test_csv_header_and_rows(self):
        csv_out = reports.render(_result(), "csv")
        lines = csv_out.strip().splitlines()
        assert lines[0].startswith("id,label,primary_type")
        assert len(lines) >= 2

    def test_html_is_document(self):
        html = reports.render(_result(), "html")
        assert html.lstrip().startswith("<!doctype html>")
        assert "<table>" in html

    def test_dot_graph(self):
        dot = reports.render(_result(), "dot")
        assert dot.startswith("digraph identity")

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError):
            reports.render(_result(), "pdf")

    def test_bundle_writes_files(self, tmp_path):
        written = reports.bundle(_result(), str(tmp_path), basename="case1")
        assert len(written) == 5
        for p in written:
            assert __import__("os").path.exists(p)

    def test_graphviz_svg_png_none_without_dot(self):
        from entity_fusion.reports import graphviz as gv
        res = _result()
        # dot binary is generally absent in this env → helpers return None or bytes
        assert gv.render_svg(res) is None or isinstance(gv.render_svg(res), bytes)
        assert gv.render_png(res) is None or isinstance(gv.render_png(res), bytes)

    def test_json_render_identities(self):
        from entity_fusion.reports import json as jr
        res = _result()
        out = jr.render_identities(res.identities)
        assert "identities" in json.loads(out)


class TestHistory:
    def test_diff_snapshots_detects_username_change(self):
        before = Entity(type=EntityType.USERNAME, value="oldhandle")
        after = Entity(type=EntityType.USERNAME, value="newhandle", id=before.id)
        eng = HistoryEngine()
        events = eng.diff_snapshots(before, after)
        assert any(e.kind == ChangeKind.USERNAME_CHANGE for e in events)

    def test_diff_detects_avatar_change(self):
        before = Entity(type=EntityType.PERSON, value="p", metadata={"avatar_sha256": "a"})
        after = Entity(type=EntityType.PERSON, value="p", id=before.id,
                       metadata={"avatar_sha256": "b"})
        events = HistoryEngine().diff_snapshots(before, after)
        assert any(e.kind == ChangeKind.AVATAR_CHANGE for e in events)

    def test_timeline_sorted(self):
        eng = HistoryEngine()
        from entity_fusion.history import TimelineEvent
        eng.record(TimelineEvent(at=200, kind=ChangeKind.OTHER))
        eng.record(TimelineEvent(at=100, kind=ChangeKind.OTHER))
        times = [e.at for e in eng.timeline()]
        assert times == [100, 200]

    def test_render_markdown(self):
        before = Entity(type=EntityType.USERNAME, value="a")
        after = Entity(type=EntityType.USERNAME, value="b", id=before.id)
        eng = HistoryEngine()
        eng.diff_snapshots(before, after)
        md = eng.render_markdown()
        assert "## Timeline" in md
