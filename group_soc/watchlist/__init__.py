"""group_soc.watchlist — monitoring targets (not verdicts) + matching."""

from .manager import WatchlistManager
from .matching import match_event
from .indicators import normalize_indicator

__all__ = ["WatchlistManager", "match_event", "normalize_indicator"]
