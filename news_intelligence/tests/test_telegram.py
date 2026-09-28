"""Tests for the pure Telegram command service + callback dispatch (no bot)."""
from news_intelligence.telegram.commands import NewsCommandService
from news_intelligence.telegram.callbacks import dispatch
from news_intelligence.telegram import keyboards


def _svc(engine):
    return NewsCommandService(engine=engine)


def test_cmd_news_overview(ingested_engine):
    out = _svc(ingested_engine).cmd_news()
    assert "News Intelligence" in out


def test_cmd_news_today(ingested_engine):
    out = _svc(ingested_engine).cmd_news_today()
    assert "Today" in out


def test_cmd_news_search(ingested_engine):
    out = _svc(ingested_engine).cmd_news_search(["LockBit"])
    assert "LockBit" in out


def test_cmd_news_actor(ingested_engine):
    out = _svc(ingested_engine).cmd_news_actor(["APT29"])
    assert "APT29" in out


def test_cmd_news_cve(ingested_engine):
    out = _svc(ingested_engine).cmd_news_cve(["CVE-2024-1234"])
    assert "CVE-2024-1234" in out


def test_cmd_news_graph(ingested_engine):
    out = _svc(ingested_engine).cmd_news_graph([])
    assert "graph" in out.lower()


def test_callback_dispatch_timeline(ingested_engine):
    svc = _svc(ingested_engine)
    out = dispatch("news:actor:timeline:APT29", service=svc)
    assert "Timeline" in out


def test_keyboard_shape():
    kb = keyboards.nav_keyboard("actor", "APT29")
    # without PTB installed, returns raw rows
    assert kb is not None
