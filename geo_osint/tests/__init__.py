"""geo_osint.tests — offline unit tests for the Geo-OSINT engine (spec §53).

All tests run with the stdlib ``unittest`` runner and require no network and no
third-party packages: the pure core (coordinate math, models, gazetteer, geocoding,
correlation, visualization, storage, reports, engine/pipeline) is exercised end to
end, and the network clients are tested via their pure offline parsers.

    python -m unittest discover -s geo_osint/tests -v
"""
