"""
cve_tracker.tests — unittest suite for the CVE subsystem.

Every test uses mocked data / temp sqlite files and never touches the network or
the bot (rule §42). Run with:

    python -m unittest discover -s cve_tracker/tests -p 'test_*.py'
"""
