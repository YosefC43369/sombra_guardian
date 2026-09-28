# ATT&CK & CAPEC Mapping

Package: `threat_actor_intelligence/mitre/`

The MITRE layer holds the reference catalogs and turns observed free text /
malware names into **validated** technique, tactic and software mappings. Nothing
is guessed: explicit ids are validated against the loaded catalog, keyword hits
are high-precision, and software matches are exact-or-alias only.

## Components

| Module | Responsibility |
|---|---|
| `attack_engine.ATTACKEngine` | Loads the ATT&CK STIX 2.1 bundle → `Technique`, `Tactic`, `Mitigation`, `Software`, `ATTACKGroup`; resolves the STIX relationship graph (`uses`, `mitigates`, `subtechnique-of`); ships an offline seed. |
| `capec_engine.CAPECEngine` | Loads CAPEC (JSON / STIX) → `CAPECPattern` with ATT&CK + CWE cross-refs; reverse index technique → patterns; offline seed. |
| `technique_mapper.TechniqueMapper` | Extracts technique ids from text: explicit `T####[.###]` (regex + catalog validation) and a curated keyword→technique lexicon. Returns auditable `TechniqueHit`s (with the matched span + method). |
| `tactic_mapper.TacticMapper` | Techniques → tactics; kill-chain coverage matrix + coverage score. |
| `software_mapper.SoftwareMapper` | `MalwareFamily` → ATT&CK `Software` by exact name/alias; folds the software's technique set into the family. |

## Loading the catalog

```python
from threat_actor_intelligence.mitre import ATTACKEngine
attack = ATTACKEngine()
attack.load_stix_bundle(enterprise_attack_json)   # MITRE CTI enterprise-attack.json
# or, offline / tests:
attack = ATTACKEngine().load_seed()
```

The engine accepts the object types ATT&CK uses: `attack-pattern` (techniques),
`x-mitre-tactic`, `course-of-action` (mitigations), `malware`/`tool` (software),
`intrusion-set` (groups) and `relationship`. Revoked/deprecated objects are
skipped. External ids (`T1059`, `TA0002`, `M1042`, `S0154`, `G0016`) are read
from the `mitre-attack` external reference so links resolve directly.

## Mapping queries

```python
attack.techniques_for_group("Cozy Bear")     # -> [Technique, ...]
attack.techniques_for_software("SUNBURST")   # -> [Technique, ...]
attack.mitigations_for("T1566")              # -> [Mitigation, ...]
attack.coverage_matrix(["T1566","T1059.001"])# -> {tactic: [technique_ids]}
```

## Technique extraction from reports

```python
from threat_actor_intelligence.mitre import TechniqueMapper
hits = TechniqueMapper(attack).map_text(
    "Actor used spearphishing attachment then PowerShell (T1027).")
# -> T1566.001 (keyword), T1059.001 (keyword), T1027 (explicit)
```

Each `TechniqueHit` records `method` (`explicit`|`keyword`), the `matched` span,
and the resolved `name`/`tactics`, so the mapping is auditable.

## Tactic coverage

```python
from threat_actor_intelligence.mitre import TacticMapper
TacticMapper(attack).summary(["T1566","T1059.001","T1486"])
# {tactics_covered, tactics_total=14, coverage_score, by_tactic:[TacticCoverage...]}
```

Enterprise tactics are ordered in kill-chain order (`ENTERPRISE_TACTICS`) so the
coverage matrix and MITRE graph render columns left-to-right.

## CAPEC

```python
from threat_actor_intelligence.mitre import CAPECEngine
capec = CAPECEngine().load_seed()           # or capec.load_json(text)
capec.patterns_for_technique("T1566")       # -> [CAPEC-98, ...]
```

CAPEC contributes only public pattern metadata (id, name, abstraction,
likelihood/severity, ATT&CK/CWE cross-refs). No exploit content.

## In the pipeline

During resolution, every report's `title + summary` is run through the
`TechniqueMapper`; matched techniques are linked onto the report and onto the
actors/families the report is about, and a `uses` relationship (actor → technique)
is emitted citing that report. Malware families are enriched via the
`SoftwareMapper` when a confident ATT&CK software name match exists.
