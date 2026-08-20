"""Second scan pass driven by the first pass's metadata.

An email scan proves an account exists but rarely names it. When a profile does
expose a handle or a link to another platform, that handle can be scanned as a
username — reaching accounts no email check can see.

Two kinds of hit come out of that, and they are not equally trustworthy: a site
a pivot named by handle, and a site where the same handle merely happens to be
taken. Every hit is scored so the difference survives into the report.
"""