# Frameworks and standards

Which frameworks Cleave measures an organization against, which standards customers are asked
for, and how each one is kept current. It is for whoever edits the catalogue or decides which
framework comes next. How a verdict is computed is in `app/compliance/coverage.py`; why the
catalogue lists a standard in full is [DECISIONS.md §209](DECISIONS.md).

## What is offered

Eighteen catalogue entries are offered, counting each version of a CIS benchmark. A framework about
one cloud is shown only to organizations connected to it, and the rest are shown to everyone
(`services/compliance.frameworks_for`). Every one can be sealed into an audit package (§208).

| Framework | Id | Version | Controls | Assessable | Reached by a rule |
|---|---|---|---|---|---|
| SOC 2 | `SOC2` | 2017 TSC, points of focus revised 2022 | 61 | 9 | 13 |
| ISO/IEC 27001 Annex A | `ISO_27001` | 2022 (Amd 1:2024) | 93 | 24 | 16 |
| PCI DSS | `PCI_DSS_4` | 4.0.1 | 64 | 25 | 21 |
| NIST CSF | `NIST_CSF_2.0` | 2.0 | 106 | 20 | 15 |
| CIS Controls | `CIS_CONTROLS_8.1` | 8.1 | 153 | 53 | 46 |
| CSA Cloud Controls Matrix | `CSA_CCM_4.1` | 4.1 | 207 | 46 | 45 |
| NIST SP 800-171 | `NIST_800_171_R2` | Rev. 2 | 110 | 44 | 34 |
| DORA | `DORA` | Regulation (EU) 2022/2554 | 27 | 6 | 6 |
| NIST SP 800-53 | `NIST_800_53` | Rev. 5 | 24 | 19 | 22 |
| GDPR | `GDPR` | 2016/679 | 11 | 8 | 10 |
| HIPAA Security Rule | `HIPAA` | 45 CFR 164 | 34 | 34 | 34 |
| NIS2 | `NIS2` | 2024/2690 | 120 | 120 | 97 |
| MITRE ATT&CK | `MITRE_ATTACK` | Enterprise | 46 | 46 | 36 |
| CIS Azure Foundations | `CIS_AZURE_2.0`, `CIS_AZURE_6.0` | 2.0, 6.0 | 151, 127 | 147, 89 | 113, 83 |
| CIS AWS Foundations | `CIS_AWS_3.0`, `CIS_AWS_7.0` | 3.0, 7.0 | 57, 70 | 54, 34 | 43, 42 |
| AWS FSBP | `AWS_FSBP` | 1.0 | 286 | 286 | 29 |

The counts are from 2 October 2026. "Reached" counts controls a rule's mapping names, including
the few the catalogue marks as not assessable. Most of the gap between a standard's size and
what a scan reaches is not a backlog: SOC 2, ISO 27001 and the CSF are mostly about how an
organization is run, and a configuration reading cannot satisfy them.

Where the text comes from:

- `app/compliance/data/standards.json`: SOC 2, ISO 27001, PCI DSS, CSF 2.0, CIS Controls v8.1,
  CSA CCM v4.1, NIST 800-171 and DORA. Titles are Cleave's own words, except CSF 2.0 and
  800-171, which are NIST's public text, and CCM, whose control names are CSA's.
- `app/compliance/data/frameworks.json`: the six kept from Prowler (§168), in the published
  wording. Tests pin this file to those six.
- `app/compliance/catalog.py`: GDPR, NIST 800-53 and the older CIS benchmarks, written out.
- Rule to control mappings: each rule's `compliance_mappings`, then `data/crosswalk.json` for
frameworks the rule does not map itself. The mappings for the CIS Controls, CCM, 800-171 and DORA
  are hand-written there.

## Which standards customers are asked for

This is a synthesis of vendor and practitioner sources, not a survey of Cleave's customers, and
the sources are linked at the end. Treat the ordering as a starting point and replace it with
what the first customers ask for.

Most companies accumulate several frameworks, in an order set by who is asking: first the one
that gates revenue, then the one that gates a particular deal, then the regulation that becomes
mandatory.

### Security assurance a buyer asks for

- **SOC 2** is the usual first request from a US enterprise buyer of a SaaS product, usually as a
  Type II report. Only a licensed firm issues it.
- **ISO/IEC 27001** is the equivalent outside the US, with certificates in the tens of
  thousands across more than 150 countries. Many companies hold both.
- **PCI DSS** applies to anyone who stores, processes or transmits card data. It is contractual
  and its scope is the cardholder data environment, which Cleave cannot know.

### Cloud and IT systems

- **CIS Benchmarks** (Azure, AWS) are the technical baselines most cloud teams are measured on.
- **CIS Controls** is the prioritized safeguard list that smaller teams adopt first, because its
  implementation groups say what to do in what order.
- **NIST CSF** is the common vocabulary for US organizations and a way to report to a board.
- **NIST SP 800-53** underlies FedRAMP and US federal work.
- **Cloud Security Alliance CCM** is the cloud-specific control matrix behind CSA STAR, the
  registry SaaS vendors publish to.

### Regulation that becomes mandatory

- **HIPAA** for US health data, **GDPR** for personal data of people in the EU, and **NIS2** for
  essential and important entities in the EU.
- **DORA** applies to EU financial entities and their ICT providers from 17 January 2025.
- **CMMC 2.0** applies to US defence contractors handling controlled unclassified information. The
  first phase began on 10 November 2025 and third-party Level 2 certification is expected to be
  required from 10 November 2026.

### Recommended next

The cloud, defence and financial-sector entries the first version of this page recommended are
built (§210). What remains, each as a new entry in `standards.json` with its own tests:

1. **NIST SP 800-171 Rev. 3** (97 requirements), when the Department of Defense moves CMMC to it.
   NIST has withdrawn Rev. 2, but CMMC Level 2 assesses Rev. 2, which is why Rev. 2 is offered.
   Following the one-version rule (§209), Rev. 3 replaces Rev. 2 on that day and does not sit
   beside it.
2. **ISO/IEC 27017 and 27018**, the cloud and personal-data extensions of ISO 27002, and
   **FedRAMP** baselines on the 800-53 catalogue if US federal work is a target. The 800-53
   catalogue here is 24 controls of several hundred, so FedRAMP means listing it in full first.
3. **The DORA technical standards** (the regulatory technical standards on the ICT risk
   framework), if a financial-sector customer asks for control-level rather than article-level
   evidence. Today a DORA row stands for its article.

Local schemes (Cyber Essentials in the UK, C5 in Germany, ISMAP in Japan) are worth adding only
when a customer in that market asks.

## Keeping them current

Every standard is revised on its own schedule, and a stale catalogue is worse than a missing one:
a customer would seal a package against a version their auditor no longer uses. Review the
sources below every quarter, and also whenever a customer or auditor names a version that is not
on this page.

| Standard | Publisher's page | What changes it | Version now |
|---|---|---|---|
| SOC 2 | [AICPA Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2/) | The AICPA revises points of focus rarely (2022); criteria unchanged since 2017 | 2017, rev. 2022 |
| ISO 27001 | [ISO/IEC 27001](https://www.iso.org/standard/27001) | A revision or amendment; 27000 was reissued in 2026, and 27001 is expected to align later | 2022, Amd 1:2024 |
| PCI DSS | [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/) | Roughly every three years, with a request for comments first | 4.0.1 |
| NIST CSF | [NIST CSF](https://www.nist.gov/cyberframework) | NIST announces revisions; 2.0 is the first since 2018 | 2.0 |
| CIS Controls | [CIS Controls](https://www.cisecurity.org/controls) | Major version every few years, minor ones between | 8.1 |
| CIS Benchmarks | [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | Several releases a year per benchmark | see catalogue |
| CSA CCM | [Cloud Controls Matrix](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) | Occasional minor versions; STAR accepts v4.1 only from March 2026 (Level 1) and December 2027 (Level 2) | 4.1 |
| NIST 800-171 | [SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r3/final) | The Department of Defense choosing a revision for CMMC, not NIST publishing one | Rev. 2 |
| DORA | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2022/2554/oj) | An amending act, or new technical standards | 2022/2554 |

### Taking in a new version

A new version is a new id and a remap. It is never an edit in place, because a sealed package
names its framework by id (§208) and must not be reinterpreted.

1. Read the publisher's change notes, and decide whether controls were added, withdrawn, renumbered
   or only reworded. Rewording alone is an edit to a title.
2. Add the new framework to `standards.json` in full, with its own id (`NIST_CSF_2.0`). Take
   identifiers from the publisher, never from memory. NIST's tool exports the CSF as a workbook
   (`https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all`), and it
   carries each subcategory's 1.1 back-references, which is how the 1.1 rules were remapped.
   The same service exports 800-171 as JSON, and CSA's CCM bundle carries the control list as a
   workbook.
3. Remap every rule. A rule's own `compliance_mappings` for a framework it maps itself, and
   `crosswalk.json` for the rest. Choose the one subcategory the rule evidences; a publisher's
   many-to-many crosswalk overclaims if taken whole.
4. Remove the old id from the catalogue, so only the latest version is offered. Sealed packages
   keep the old id in their stored rows and still verify.
5. Update the tests that pin counts (`tests/unit/test_standards_catalog.py`), run
   `python apps/api/scripts/generate_rule_catalog.py` to regenerate `docs/RULE_CATALOG.md`, and
   record the change in `DECISIONS.md`.
6. Update this page's table and the "Version now" column.

A mapping to an identifier the catalogue does not define fails `tests/unit/test_compliance.py`,
so a withdrawn control cannot stay in a rule.

### What is not automated

Nothing detects that a standard has been revised. The review above is a person reading a page.
The cheapest automation worth adding is a scheduled check that fetches NIST's CSF export and the
CIS Controls page and compares counts and version strings with `standards.json`, opening an issue
on a difference. Sources that sit behind a form or a paywall (ISO, PCI, SOC 2) stay a manual
read. That check is not built.

## See also

- [DECISIONS.md §209](DECISIONS.md), why the standards are listed in full, and
  [§210](DECISIONS.md), the cloud, defence and financial-sector additions.
- [DECISIONS.md §168](DECISIONS.md), why the older frameworks are data and the engine is one.
- [Native coverage backlog](NATIVE_COVERAGE_BACKLOG.md), what no rule checks yet.

## Sources

- [NIST CSF 2.0 reference data](https://csrc.nist.gov/projects/cprt/data-formats) and the
  [CSF page](https://www.nist.gov/cyberframework): 106 subcategories in 22 categories under six
  functions, published in February 2024.
- [CIS Critical Security Controls](https://www.cisecurity.org/controls): v8.1, June 2024, 18
  controls and 153 safeguards. No later release exists as of this page.
- [PCI DSS v4.0.1](https://www.pcisecuritystandards.org/document_library/): published 11 June
  2024; v4.0 retired on 31 December 2024 and the future-dated requirements became mandatory on 31
  March 2025. A vendor blog reports a request for comments on the next version in mid-2026; check
  the Council's page.
- [ISO/IEC 27001:2022 Amendment 1:2024](https://hightable.io/iso270012022-amendment-1-absolutely-everything-you-need-to-know/):
  adds a climate-change consideration and leaves Annex A unchanged. The transition from the 2013
  edition ended on 31 October 2025.
- [AICPA Trust Services Criteria](https://www.aicpa-cima.com/search/5+trust+services+criteria):
  the 2017 criteria with points of focus revised in 2022.
- [CSA CCM v4.1 transition timeline](https://cloudsecurityalliance.org/blog/2026/02/19/ccm-v4-1-transition-timeline)
  and the CCM v4.1 workbook (207 controls in 17 domains, released 28 January 2026), downloaded
  from the [CCM page](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1).
- [NIST SP 800-171 Rev. 2](https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final), exported from
  NIST's reference tool: 110 requirements in 14 families.
- [CMMC timeline](https://secureframe.com/hub/cmmc/proposed-final-rule) and the
  [DORA overview](https://www.jonesday.com/en/insights/2025/01/digital-operational-resilience-act-now-in-effect-for-financial-sector).
- Adoption, from practitioner comparisons:
  [Cloudaware](https://cloudaware.com/blog/cloud-security-compliance-standards/),
  [Compyl](https://compyl.com/blog/compliance-framework-comparison-soc2-iso27001-hipaa-pci-dss/)
  and [Datapath](https://www.mydatapath.com/blog/soc-2-vs-iso-27001-compliance-framework/).
