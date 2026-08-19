"""Scores how strongly a cross-scan hit is tied to the scanned target.

A username sweep proves a handle is registered somewhere; it cannot prove the
account belongs to the person who was scanned. Common handles collide, and a
single sweep routinely turns up several unrelated people holding the same one
alongside its real owner, so a sweep hit is a lead until something ties it back.

The tie is drawn from *confirmed* hits: accounts a pivot named by site and
handle, which the target's own profile pointed at. Their names, personal
domains and profile URLs become the anchors every other hit is measured against.
"""
