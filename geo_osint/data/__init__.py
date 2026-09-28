"""
geo_osint.data — curated, verifiable public-domain reference datasets.

These are finite tables of stable public facts (ISO country data, a major-place
gazetteer, cloud-region locations, IXP/cable references). They let the pure core
geocode, reverse-geocode and map entirely offline, with zero third-party
dependencies, and are extended at runtime by the network map clients. Nothing
here is generated or guessed: each row is a well-known public fact, and
coordinates carry honest precision.
"""

from . import countries, cities

__all__ = ["countries", "cities"]
