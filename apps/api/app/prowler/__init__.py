"""The second engine: Prowler's checks, run by the scanner service and read here.

Cleave runs two engines over every scan (DECISIONS.md section 150). The native
rule engine (``app/rules``) evaluates the raw captures Cleave's own collectors
stored, and owns everything the graph needs. Prowler, running in the separate
``apps/scanner`` service against the same scope, supplies the breadth: several
hundred configuration checks and the compliance frameworks mapped to them.

This package is everything the API knows about Prowler, and none of it imports
Prowler. Three modules:

* ``catalog`` -- the generated description of every Prowler check Cleave knows
  about (``data/catalog.json``, built by ``tools/prowler/build_catalog.py``).
* ``rules`` -- each enabled check as a :class:`~app.rules.base.SecurityRule`,
  so findings, risks, compliance and verification treat its results exactly
  as they treat a native rule's.
* ``ingest`` -- a stored capture turned into verdicts: which asset each result
  is about, what an absent result means, and where the two engines disagree.
"""
