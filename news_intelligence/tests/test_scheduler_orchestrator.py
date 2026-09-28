"""Tests for the orchestrator cycle and scheduler feed management (offline)."""
from news_intelligence.orchestrator import Orchestrator
from news_intelligence.scheduler import Scheduler


def test_orchestrator_cycle_offline(config, store, corpus, now):
    orch = Orchestrator(config=config, store=store)
    res = orch.run_cycle(articles=corpus, now=now)
    assert res.articles_collected == len(corpus)
    assert res.pipeline["ingested"] >= 4
    assert res.campaigns >= 0
    assert res.integration is not None
    assert orch.last_run() is not None


def test_scheduler_ensures_feeds(config, store):
    sched = Scheduler(config=config, store=store)
    created = sched.ensure_feeds()
    assert created > 0
    feeds = store.list_feeds()
    assert feeds
    # feed due logic
    assert any(f.due(now=9_999_999_999) for f in feeds)


def test_scheduler_status(config, store):
    sched = Scheduler(config=config, store=store)
    sched.ensure_feeds()
    st = sched.status()
    assert st["feeds"] > 0
