# Security Evidence Validation Campaign

This document captures the concrete validation basis that was finally used for SecProj Chapter 6 in the fork `Castrolium/drawio-desktop`. The original planning draft reserved a frozen 4-run campaign for version `29.6.6`. The actually observed and report-relevant series on **15. April 2026** used version `29.3.6`; Chapter 6 therefore evaluates the observed series instead of retrofitting the plan.

## 1. Scope and Goal

The campaign validates three core claims of the Security Evidence Pack MVP under real GitHub Actions conditions:

- reproducibility across repeated dry-runs,
- completeness and formal correctness of the packaged artifact,
- traceability from artifact and summary back to workflow run and, for the real run, branch and pull request.

The campaign does not store raw artifacts or log downloads in the repository. Only this procedure, the resulting evaluation text, and summarized findings stay tracked in git.

## 2. Baseline Freeze and Observed Series

### Source of truth

- Repository for the campaign: `Castrolium/drawio-desktop`
- Workflow branch for the frozen baseline: `dev`
- Frozen workflow baseline date: **15. April 2026**
- Frozen workflow merge commit in the fork: `ee7ffa541c043397c97e9d404479efadeac07c8f`
- Baseline pull request: [PR #8](https://github.com/Castrolium/drawio-desktop/pull/8) (`Update GitHub Actions to Node 24-capable majors`)

### Planned baseline facts

These facts defined the intended frozen baseline for the campaign:

- Workflow file: `.github/workflows/prepare-release.yml`
- `actions/checkout@v6`
- `actions/setup-node@v6`
- `package-manager-cache: false`
- `actions/upload-artifact@v6`
- artifact retention: `90` days
- controlled Node version: `24`
- Snyk CLI version: `v1.1301.0`

### Observed caveats

The final report-relevant run series is close to, but not identical with, the planned frozen baseline:

- Run A was executed before the fully frozen `v6` action baseline and still used `actions/*@v4`.
- Run B was executed on a feature branch.
- Runs C and D were executed on the frozen merge commit `ee7ffa541c043397c97e9d404479efadeac07c8f`.
- The evaluation keeps these deviations visible instead of smoothing them out.

### Access and secret assumptions

- GitHub repository permission for `Castrolium` on the fork was verified as `admin` on **15. April 2026**.
- `GITHUB_TOKEN` is required for branch push and PR creation in the real run.
- `SNYK_TOKEN` must be configured in the fork so the successful Snyk export path can be validated.

### Freeze rule

No workflow file, release script, or evidence-packaging change should land between Run A and Run D. Because the observed run series already contains two pre-freeze deviations, these are documented in Section 10 and carried into Chapter 6 as methodical limitations.

## 3. Fixed Campaign Inputs for the Final Evaluation

At planning time, `29.6.6` was reserved as the intended comparison candidate. The final evaluation, however, uses the actually observed run series for `29.3.6`, because this is the series that is publicly evidenced through workflow metadata, job logs, artifact references, and the productive PR path.

| Input | Observed evaluation value | Note |
|-------|---------------------------|------|
| `version` | `29.3.6` | Logged in all four primary runs through artifact name and workflow output. |
| `drawio_ref` | `v29.3.6` | Logged consistently in all four primary runs. |
| `drawio_commit` | `8b988d670049c4cbf1713decab0e922d94533b91` | Logged consistently in all four primary runs. |
| `dry_run` | `true` for A/B/C, `false` for D | Matches the intended 3+1 comparison design. |
| Workflow baseline | Strictly frozen only from Run C onward | Run A and Run B remain valid observed dry-runs, but weaken a strict same-baseline interpretation. |

## 4. Run Matrix

Use the actually observed run series for the evaluation. Only `dry_run` changes for Run D; the version and `drawio` context remain stable across the primary dataset.

| Run | Mode | Date | Run metadata | Workflow URL | Artifact reference | Notes |
|-----|------|------|--------------|--------------|--------------------|-------|
| A | Dry-Run | **15. April 2026** | Run ID `24443362290`; ref `refs/heads/dev`; commit `6325d46993baac8aa8207580545a814496bd8c61` | [Run A](https://github.com/Castrolium/drawio-desktop/actions/runs/24443362290) | [artifact 6445751988](https://github.com/Castrolium/drawio-desktop/actions/runs/24443362290/artifacts/6445751988) | Success after `129` s; artifact size `71569`; upload digest `47a692c2647bf594aaf70505bb218516316f11612ca247d769a2a037c7b5c536`; still used `actions/*@v4`; requested retention `365`, capped by GitHub to `90`. |
| B | Dry-Run | **15. April 2026** | Run ID `24444661594`; feature-branch ref; commit `45b9ec1f2aed71214aa89fdd7941744e022fad1c` | [Run B](https://github.com/Castrolium/drawio-desktop/actions/runs/24444661594) | [artifact 6446274954](https://github.com/Castrolium/drawio-desktop/actions/runs/24444661594/artifacts/6446274954) | Success after `128` s; artifact size `71580`; upload digest `73038d45bc4dc3cfe301c9f9e62f33b41db3b603d0dee3a3defcae0ce5977683`; dry-run on a feature branch. |
| C | Dry-Run | **15. April 2026** | Run ID `24445244875`; ref `refs/heads/dev`; commit `ee7ffa541c043397c97e9d404479efadeac07c8f` | [Run C](https://github.com/Castrolium/drawio-desktop/actions/runs/24445244875) | [artifact 6446531712](https://github.com/Castrolium/drawio-desktop/actions/runs/24445244875/artifacts/6446531712) | Success after `121` s; artifact size `71567`; upload digest `364eedbdd2f99f2646a6a358a9624f9c1e19a22b9b4f1daa98cd72f0bc725ed9`; first run on the fully frozen merge commit. |
| D | Real-Run | **15. April 2026** | Run ID `24446147424`; ref `refs/heads/dev`; commit `ee7ffa541c043397c97e9d404479efadeac07c8f` | [Run D](https://github.com/Castrolium/drawio-desktop/actions/runs/24446147424) | [artifact 6446910689](https://github.com/Castrolium/drawio-desktop/actions/runs/24446147424/artifacts/6446910689) | Success after `127` s; artifact size `71566`; upload digest `903a55157fcf4ef6be1dcb7d76287b2d6bc116b16fcbe35d88dff13847684dba`; created branch `releases/v29.3.6` and [PR #9](https://github.com/Castrolium/drawio-desktop/pull/9). |

Across all four primary runs, the logs consistently report `version` `29.3.6`, `drawio_ref` `v29.3.6`, `drawio_commit` `8b988d670049c4cbf1713decab0e922d94533b91`, `Node.js` `v24.14.1`, `npm` `11.11.0`, `Electron` `39.8.7`, Snyk status `no-findings`, and Security Summary status `ready`.

## 5. Raw Data Storage Outside the Repository

The intended external archive layout stays as the recommended raw-data structure:

```text
C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\
  A\
    metadata.json
    step-summary.md
    log-excerpt.txt
    artifact\
      security-evidence-pack-v29.3.6\
  B\
    metadata.json
    step-summary.md
    log-excerpt.txt
    artifact\
      security-evidence-pack-v29.3.6\
  C\
    metadata.json
    step-summary.md
    log-excerpt.txt
    artifact\
      security-evidence-pack-v29.3.6\
  D\
    metadata.json
    step-summary.md
    log-excerpt.txt
    artifact\
      security-evidence-pack-v29.3.6\
```

For the post-hoc evaluation on **22. April 2026**, this archive was no longer present locally. Metadata fields were therefore reconstructed from workflow metadata, public job logs, artifact references, and the productive PR trace. Raw artifacts still remain intentionally outside the git repository.

## 6. Per-Run Data Capture Checklist

For every run, capture the same evidence set:

- workflow run URL,
- run ID,
- triggering branch/ref and commit,
- `drawio_ref` and resolved `drawio` commit,
- step summary export,
- short log excerpt for the security evidence steps,
- downloaded and unpacked artifact,
- artifact tree, file sizes, and SHA-256 hashes,
- summary status and evidence inventory,
- for Run D only: created release branch, pushed commit SHA, and PR URL.

If a metadata file is missing, reconstruct the missing fields from workflow metadata and logs and explicitly record any remaining gap instead of guessing it.

## 7. External Metadata File

Each unpacked artifact should have a sibling `metadata.json` outside the repository so the analyzer can validate traceability against workflow facts.

Example reconstructed metadata for Run A:

```json
{
  "label": "Dry-Run A",
  "dryRun": true,
  "runId": "24443362290",
  "runUrl": "https://github.com/Castrolium/drawio-desktop/actions/runs/24443362290",
  "workflowName": "Prepare Release",
  "gitRef": "refs/heads/dev",
  "gitCommit": "6325d46993baac8aa8207580545a814496bd8c61",
  "drawioRef": "v29.3.6",
  "drawioCommit": "8b988d670049c4cbf1713decab0e922d94533b91",
  "triggeredAt": "2026-04-15T08:03:08Z",
  "durationSeconds": 129,
  "artifactDownloadPath": "not archived locally",
  "stepSummaryPath": "not archived locally",
  "logExcerptPath": "reconstructed from public GitHub job logs",
  "notes": "Observed run preceding the fully frozen v6 action baseline."
}
```

For Run D, add:

```json
{
  "branchName": "releases/v29.3.6",
  "prUrl": "https://github.com/Castrolium/drawio-desktop/pull/9"
}
```

## 8. Analysis Commands

The analysis scripts remain the canonical CLI interface for a full rerun. They expect unpacked artifacts and metadata files and can run later on any machine that has Node.js 24 available.

### 8.1 Analyze each run

```powershell
node .\build\analyze-security-evidence-run.mjs `
  --artifact-dir "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\A\artifact" `
  --metadata-file "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\A\metadata.json" `
  --output-file "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\A\analysis.json"
```

Repeat for `B`, `C`, and `D`.

### 8.2 Compare the full campaign

```powershell
node .\build\compare-security-evidence-runs.mjs `
  --analysis-file "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\A\analysis.json" `
  --analysis-file "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\B\analysis.json" `
  --analysis-file "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\C\analysis.json" `
  --analysis-file "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\D\analysis.json" `
  --title "Security Evidence Validation Campaign" `
  --output-json "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\campaign-report.json" `
  --output-markdown "C:\Users\nicoc\Downloads\Files\security-evidence-validation\2026-04-15\chapter6-validation.md"
```

For the reconstructed evaluation state on **22. April 2026**, these commands could not be rerun end-to-end because the unpacked raw artifacts were no longer archived locally and the GitHub artifact ZIPs were not directly redownloadable without authenticated access. The Chapter 6 text therefore mirrors the same criteria, but applies them to workflow metadata, artifact references, job logs, and PR metadata.

## 9. Evaluation Table for Chapter 6

Use the generated Markdown as the primary source when a complete external archive is available. For the current repository state, the evaluation table below summarizes the observed results that were reconstructed from the available evidence.

| Kriterium | Soll | Ist | Bewertung | Evidenz |
|-----------|------|-----|-----------|---------|
| Vollstaendigkeit | Alle erfolgreichen Runs enthalten 100 Prozent der Pflichtdateien in der Sollstruktur und genau einen Snyk-Nachweis. | In `4/4` Primaerruns wurde `security-evidence-pack-v29.3.6` mit denselben sieben Pflichtpfaden paketiert und hochgeladen. | `Erfuellt` | Run A bis D, Packaging-Logs, Artefaktseiten |
| Formalkorrektheit | Audit-JSON, Snyk-Nachweis, SBOM und HTML-Summary werden erfolgreich erzeugt und bestehen die formale Workflow-Validierung. | In `4/4` Primaerruns liefen Preflight, Integrationstests, Snyk-Export, SBOM, HTML-Summary, Packaging und Artifact-Upload erfolgreich; Summary-Status war jeweils `ready`, Snyk-Status jeweils `no-findings`. | `Erfuellt` | Run A bis D, Job-Logs |
| Reproduzierbarkeit | Dry-Run A/B/C liefern dieselben Kernaussagen; Unterschiede sind nur in volatilen Feldern zulaessig. | `3/3` Dry-Runs zeigen denselben Artefaktnamen, dieselben sieben Pflichtpfade, dieselben `drawio`-Metadaten und denselben Summary-/Snyk-Grundstatus; die Serie ist aber nicht vollstaendig auf einem identischen Workflow-Baseline-Commit entstanden und die Upload-Digests unterscheiden sich. | `Teilweise erfuellt` | Run A bis C, Logs, Artifact-Digests |
| Nachvollziehbarkeit | Version, Commit, Ref, `drawio_ref`, Run-ID/-URL und Artefaktname sind konsistent verknuepft. | `4/4` Primaerruns lassen sich ueber Run-URL, Run-ID, Ref, Commit, Artefaktname sowie `drawio_ref` und `drawio_commit` rekonstruieren; Run D dokumentiert zusaetzlich Release-Branch und PR. | `Erfuellt` | Run A bis D, PR #9 |
| Produktivpfad (`dry_run=false`) | Mindestens ein echter Run erzeugt denselben Evidence-Pack-Typ und dokumentiert Branch und PR. | Run D erzeugte das Artefakt, legte `releases/v29.3.6` an und erstellte PR #9. | `Erfuellt` | Run D, PR #9 |

### Interpretation per criterion

**Vollstaendigkeit.** Gemessen wurde, welche Zielpfade das Packaging pro Run tatsaechlich in das Artefakt uebernommen hat. Beobachtet wurden in allen vier Primaerruns dieselben sieben Pflichtpfade: `summary/security-summary.html`, `release/release-notes.md`, `scans/npm/audit-results.json`, `scans/npm/audit-report.txt`, `scans/npm/outdated-report.txt`, `scans/snyk/snyk-report.json` und `sbom/sbom.cdx.json`. Daraus folgt, dass die Pflichtvollstaendigkeit fuer die ausgewertete Serie als erfuellt gilt.

**Formalkorrektheit.** Gemessen wurden die erfolgreichen Workflow-Schritte fuer Integrationstests, Snyk-Export, SBOM-Generierung, HTML-Summary, Packaging und Upload. Beobachtet wurde in allen vier Primaerruns ein erfolgreicher Abschluss dieser Schritte ohne dokumentierte Vertragsverletzung; die Summary wurde jeweils mit Status `ready` und der Snyk-Teil jeweils mit `no-findings` protokolliert. Daraus folgt eine positive Bewertung der formalen Brauchbarkeit, auch wenn keine nachtraegliche zweite Parser-Pruefung auf den nicht mehr lokal archivierten ZIPs moeglich war.

**Reproduzierbarkeit.** Gemessen wurden die stabilen Kernaussagen der Dry-Runs: Artefaktname, Pflichtpfade, `drawio_ref`, `drawio_commit`, Summary-Status und Snyk-Grundstatus. Beobachtet wurden hier keine fachlichen Widersprueche zwischen A, B und C. Gleichzeitig ist die Serie methodisch eingeschraenkt, weil Run A noch vor dem vollstaendig eingefrorenen `v6`-Action-Stand lief, Run B auf einem Feature-Branch ausgefuehrt wurde und sich die Upload-Digests leicht unterscheiden. Deshalb wird die Reproduzierbarkeit nicht als vollstaendig, sondern nur als teilweise erfuellt bewertet.

**Nachvollziehbarkeit.** Gemessen wurde, ob sich Artefakt, Workflow-Kontext und `drawio`-Kontext eindeutig zueinander zuordnen lassen. Beobachtet wurde fuer alle vier Primaerruns eine saubere Rueckverfolgung ueber Run-ID, Run-URL, Git-Ref, Git-Commit, Artefaktname sowie `drawio_ref` und `drawio_commit`; fuer Run D kommt der produktive Release-Branch mit PR #9 hinzu. Die Nachvollziehbarkeit gilt damit fuer die ausgewertete Serie als erfuellt.

**Produktivpfad.** Gemessen wurde, ob ein echter `dry_run=false`-Lauf denselben Evidence-Pack-Typ erzeugt und den Release-Pfad bis zu Branch und PR belegt. Beobachtet wurde dies in Run D: Das Artefakt wurde hochgeladen, `releases/v29.3.6` angelegt und [PR #9](https://github.com/Castrolium/drawio-desktop/pull/9) erstellt. Zusaetzlich zeigt der spaetere Real-Run `24456080444`, dass ein Artefakt sogar dann bereits verfuegbar bleiben kann, wenn der Produktivpfad spaeter in `Commit changes` scheitert. Das Kernkriterium des Produktivpfads ist damit erfuellt; die Fehlerfallbeobachtung bleibt jedoch nur zusaetzliche Evidenz.

## 10. Deviations and Findings Log

Record only summarized deviations here. Keep raw logs outside the repository.

| Date | Run | Observation | Impact | Follow-up |
|------|-----|-------------|--------|-----------|
| **15. April 2026** | Campaign baseline | The planning draft reserved version `29.6.6`, but the actually observed report-relevant series used `29.3.6`. | The evaluation must use the belegbare `29.3.6` series instead of the planned `29.6.6` series. | Carry the deviation explicitly into Chapter 6 and do not normalize it away. |
| **15. April 2026** | Run A | Executed before the fully frozen `v6` action baseline and still requested artifact retention `365`, which GitHub capped to `90`. | Weakens a strict same-baseline interpretation and exposes the platform retention limit. | Keep Run A as observed evidence, but document the caveat. |
| **15. April 2026** | Run B | Dry-run executed on a feature branch instead of `dev`. | Weakens strict reproducibility under identical workflow inputs. | Keep Run B as observed evidence, but rate reproducibility conservatively. |
| **15. April 2026** | Supplementary real run `24456080444` | Artifact upload completed, but `Commit changes` failed later with `nothing to commit, working tree clean`. | Supports the claim that evidence can remain available despite a later workflow failure, but does not replace the planned failure-case validation for all error classes. | Use as supplementary evidence in Chapter 6, not as a replacement for the 4-run core matrix. |
| **22. April 2026** | Post-hoc reconstruction | The intended external raw-data archive was no longer present locally and artifact ZIP re-download was not directly available without authenticated access. | Analyzer CLI could not be rerun end-to-end on the reconstructed dataset. | Base Chapter 6 on workflow metadata, logs, artifact references, and PR metadata until the raw archive is restored. |

## 11. Screenshots and Report References

Keep screenshot files outside the repository and reference them here for the final report.

- Workflow UI screenshot for Run A: use [Run A](https://github.com/Castrolium/drawio-desktop/actions/runs/24443362290)
- Artifact tree screenshot for Run A: not archived locally; use [artifact 6445751988](https://github.com/Castrolium/drawio-desktop/actions/runs/24443362290/artifacts/6445751988) together with the packaging log
- Comparison report screenshot or export: not generated from a locally archived dataset; use [SECURITY_EVIDENCE_CHAPTER6_EVALUATION.md](./SECURITY_EVIDENCE_CHAPTER6_EVALUATION.md) as the repo-tracked summary
- PR screenshot for Run D: use [PR #9](https://github.com/Castrolium/drawio-desktop/pull/9)

## 12. Completion Rule

For the Chapter 6 evaluation, the campaign is analytically complete when Sections 4, 9, 10, and 11 of this document are filled and all remaining data gaps are explicitly documented. A fully repeatable rerun additionally requires recovering or re-exporting the unpacked artifacts so the analyzer CLI can be executed end-to-end.
