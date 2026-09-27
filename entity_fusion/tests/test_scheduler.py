"""Tests for entity_fusion.scheduler — bounded-concurrency async batch runner."""

import asyncio
import pytest

from entity_fusion.scheduler import AsyncScheduler, RateLimiter


def run(coro):
    return asyncio.run(coro)


class TestAsyncScheduler:
    def test_all_succeed(self):
        async def make(i):
            async def _c():
                await asyncio.sleep(0)
                return i * 2
            return _c
        async def go():
            factories = [ (lambda i=i: _mk(i)) for i in range(5)]
            return await AsyncScheduler(concurrency=3).run(factories)
        async def _mk(i):
            await asyncio.sleep(0)
            return i * 2
        res = run(go())
        assert res.stats()["ok"] == 5
        assert sorted(res.values) == [0, 2, 4, 6, 8]

    def test_failure_isolated(self):
        async def ok():
            return "ok"
        async def boom():
            raise RuntimeError("bad")
        res = run(AsyncScheduler().run([lambda: ok(), lambda: boom(), lambda: ok()]))
        assert res.stats() == {"total": 3, "ok": 2, "failed": 1}
        assert res.values == ["ok", "ok"]
        assert res.errors and "RuntimeError" in res.errors[0]

    def test_concurrency_bound_respected(self):
        state = {"current": 0, "peak": 0}
        async def task():
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
            await asyncio.sleep(0.01)
            state["current"] -= 1
            return 1
        run(AsyncScheduler(concurrency=2).run([lambda: task() for _ in range(6)]))
        assert state["peak"] <= 2

    def test_rate_limited_scheduler_runs(self):
        async def task():
            return 1
        res = run(AsyncScheduler(concurrency=4, rate=100).run(
            [lambda: task() for _ in range(4)]))
        assert res.stats()["ok"] == 4

    def test_timeout_becomes_error(self):
        async def slow():
            await asyncio.sleep(1.0)
            return 1
        res = run(AsyncScheduler(per_task_timeout=0.01).run([lambda: slow()]))
        assert res.stats()["failed"] == 1


class TestRateLimiter:
    def test_acquire_returns(self):
        rl = RateLimiter(rate=1000)
        run(rl.acquire())  # should return promptly

    def test_invalid_rate(self):
        with pytest.raises(ValueError):
            RateLimiter(rate=0)
