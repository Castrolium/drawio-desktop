# draw.io Desktop Release Process

**Document ID:** REL-PROC-DESKTOP-001<br>
**Version:** 1.4<br>
**Last Updated:** 2026-04-01<br>
**Owner:** Engineering Team

---

## 1. Purpose

This document defines the release process for draw.io Desktop. Automated controls via GitHub Actions handle repeatable tasks, while manual steps focus on verification and approval.

**Repository:** https://github.com/jgraph/drawio-desktop  
**Submodule:** drawio (core editor)  
**CI/CD:** GitHub Actions

---

## 2. Controlled Tooling

Tooling versions are pinned in the GitHub Actions workflows to ensure reproducible builds.

| Tool | Version | Controlled In |
|------|---------|---------------|
| Node.js | 24.x (LTS) | `.github/workflows/*.yml` |
| npm | (bundled with Node) | - |
| Snyk CLI | `v1.1301.0` | `.github/workflows/prepare-release.yml` |

> **Note:** npm is bundled with Node.js, ensuring consistent versions across environments.

When updating tooling versions:
1. Update the version in all workflow files
2. Test locally with matching versions
3. Document the change in the PR

---

## 3. Roles

| Role | Responsibility |
|------|----------------|
| **Release Lead** | Triggers workflow, verifies output, approves release |
| **Reviewer** | Reviews changes, provides approval before publish |

> **Small Team Note:** Release Lead and Reviewer should be different people when possible. For solo releases, rely on automated checks and document the reason.

---

## 4. Release Procedure

### 4.1 Automated Preparation (GitHub Actions)

The `prepare-release` workflow automates:
- Updating drawio submodule to target ref (with recursive submodule init)
- Updating version in package.json
- Exporting a Snyk JSON dependency report for the desktop package
- Generating a CycloneDX JSON SBOM for the desktop npm project
- Running `npm audit` and failing on critical/high vulnerabilities
- Running `npm outdated` for review
- Generating a self-contained HTML security summary for the artifact
- Committing changes and creating version tag
- Packaging security evidence into a structured artifact
- Uploading the security evidence artifact

**To trigger:**

1. Go to Actions -> "Prepare Release"
2. Click "Run workflow"
3. Enter:
   - **version:** The release version (e.g., `29.0.4`)
   - **drawio_ref:** (Optional) Specific tag/commit. Defaults to `v{version}`
   - **dry_run:** Check to validate without committing

**What happens:**

```text
+-----------------------------------------------------------------+
| Workflow: prepare-release                                       |
+-----------------------------------------------------------------+
| 1. Validate version format (X.Y.Z)                              |
| 2. Checkout with submodules (recursive)                         |
| 3. Setup Node.js 24.x                                           |
| 4. Update drawio submodule -> target ref                        |
|    \-> Update nested submodules (recursive)                     |
| 5. Update package.json version                                  |
| 6. npm install                                                  |
| 7. Export Snyk JSON report (`scans/snyk/snyk-report.json`)     |
|    \-> On technical failure, save `snyk-export-error.txt`       |
| 8. Generate SBOM (`sbom/sbom.cdx.json`)                         |
| 9. Generate release notes                                       |
| 10. npm audit -> FAIL if critical/high vulns                    |
| 11. npm outdated -> report only                                 |
| 12. Generate HTML summary (`summary/security-summary.html`)     |
| 13. Package + upload security evidence artifact                 |
| 14. Enforce post-upload security gates                          |
| 15. Commit + push                                               |
| 16. Create + push tag v{version}                                |
| 17. Build workflows trigger automatically                       |
+-----------------------------------------------------------------+
```

**Evidence produced:**
- Workflow run log (retained by GitHub)
- `security-evidence-pack-v{VERSION}` artifact containing:
  - `summary/security-summary.html`
  - `release/release-notes.md`
  - `scans/npm/audit-results.json`
  - `scans/npm/audit-report.txt`
  - `scans/npm/outdated-report.txt`
  - `scans/snyk/snyk-report.json` on successful export
  - `scans/snyk/snyk-export-error.txt` if the Snyk export fails technically
  - `sbom/sbom.cdx.json`
- Job summary with version details plus audit and Snyk results

**Secret required for Snyk export:**
- `SNYK_TOKEN` must be configured as a repository or organization secret.
- Snyk findings are documented in the artifact but do not block the workflow by themselves.
- A technical Snyk export failure blocks the release only after the artifact upload, so evidence remains available.

### 4.2 Pre-Release Verification

Before triggering the workflow:

| Check | Item |
|---|------|
| [ ] | Release scope documented (what's included) |
| [ ] | All feature changes merged to dev branch |
| [ ] | Target drawio ref exists and is tested |

### 4.3 Local Test-Run and Troubleshooting (First Pass)

Run this local sequence before triggering the release workflow to catch setup and artifact issues early.

1. **Validate dependencies and scripts**
   - `npm install`
   - `npm run test:security-evidence`
2. **Generate required inputs**
<<<<<<< ours
   - Export `SNYK_TOKEN` in your shell before running Snyk locally
   - Run `snyk test --json-file-output=snyk-report.json`
   - `npm run generate-sbom`
   - Prepare `release-notes.md` in repository root
   - Capture scan outputs in repository root:
     - `audit-results.json`
     - `audit-report.txt`
     - `outdated-report.txt`
     - `snyk-report.json`
3. **Generate HTML summary**
   - `npm run generate-security-summary`
   - By default, the script writes `summary/security-summary.html`
4. **Package artifact locally**
   - `npm run package-security-evidence`
   - By default, the script uses `package.json` version when `--version` is not provided
5. **Troubleshoot failures**
   - If packaging fails with `Missing required evidence file`, generate or copy the missing file to repository root
   - If packaging fails with `Invalid JSON`, regenerate the referenced JSON file and validate syntax
   - If packaging fails with `Invalid SBOM format`, regenerate SBOM and ensure `bomFormat` is `CycloneDX`
   - If summary generation fails, inspect the referenced evidence input and regenerate the missing or invalid file
   - If Snyk export fails technically, create or inspect `snyk-export-error.txt` and re-run after fixing the export issue
6. **Confirm output structure**
   - Check that output folder `security-evidence-pack-v{VERSION}` exists
   - Verify required files:
     - `summary/security-summary.html`
=======
   - `npm run generate-sbom`
   - Prepare `release-notes.md` in repository root
   - Capture npm scan outputs in repository root:
     - `audit-results.json`
     - `audit-report.txt`
     - `outdated-report.txt`
3. **Package artifact locally**
   - `npm run package-security-evidence`
   - By default, the script uses `package.json` version when `--version` is not provided
4. **Troubleshoot failures**
   - If packaging fails with `Missing required evidence file`, generate or copy the missing file to repository root
   - If packaging fails with `Invalid JSON`, regenerate the referenced JSON file and validate syntax
   - If packaging fails with `Invalid SBOM format`, regenerate SBOM and ensure `bomFormat` is `CycloneDX`
5. **Confirm output structure**
   - Check that output folder `security-evidence-pack-v{VERSION}` exists
   - Verify required files:
>>>>>>> theirs
     - `release/release-notes.md`
     - `scans/npm/audit-results.json`
     - `scans/npm/audit-report.txt`
     - `scans/npm/outdated-report.txt`
<<<<<<< ours
     - `scans/snyk/snyk-report.json` or `scans/snyk/snyk-export-error.txt`
=======
>>>>>>> theirs
     - `sbom/sbom.cdx.json`

### 4.4 Monitor Build

After the prepare-release workflow completes:

1. Verify the build workflows triggered automatically
2. Monitor build status in Actions tab
3. All platform builds must succeed before proceeding

**Evidence:** Link to successful build run: `_______________`

### 4.5 Publish Release

After all build workflows complete successfully:

1. Go to GitHub Releases - a draft release will have been created with all artifacts
2. Verify all platform builds are present (Windows builds are automatically signed via CI using `CSC_LINK` secret)
3. Add release notes (Section 8)
4. **Obtain Reviewer approval** (Section 5)
5. Click "Publish release"

---

## 5. Approval

Before publishing, the Reviewer verifies:

| Check | Requirement |
|---|-------|
| [ ] | Workflow completed successfully |
| [ ] | HTML summary is present as `summary/security-summary.html` |
| [ ] | SBOM was generated and packaged as `sbom/sbom.cdx.json` |
| [ ] | Snyk export is present as `scans/snyk/snyk-report.json` |
| [ ] | npm audit shows no critical/high vulnerabilities |
| [ ] | Build workflows passed for all platforms |
| [ ] | Test cases passed (Section 6) |

| | Name | Date |
|---|------|------|
| **Release Lead** | | |
| **Reviewer** | | |

> **Solo Release:** Document reason, ensure all automated checks pass, perform extended testing.

---

## 6. Test Cases

Run against the built application before publishing.

### Critical (Must Pass)

| ID | Test | Expected | Pass |
|----|------|----------|------|
| T01 | Launch application | Main window displays | [ ] |
| T02 | Create new diagram | Blank canvas opens | [ ] |
| T03 | Add shapes | Shapes render, move, resize | [ ] |
| T04 | Save file | Saves without error | [ ] |
| T05 | Open file | Displays correctly | [ ] |
| T06 | Help > About | Shows correct version | [ ] |

### Standard

| ID | Test | Expected | Pass |
|----|------|----------|------|
| T07 | Export PNG/PDF/SVG | Valid output | [ ] |
| T08 | Undo/Redo | Actions reverse | [ ] |

### Security

| ID | Check | Method | Pass |
|----|-------|--------|------|
| S01 | No external scripts | DevTools Network tab | [ ] |
| S02 | No data exfiltration | Monitor during save | [ ] |
| S03 | Security evidence artifact contains a valid CycloneDX SBOM | Review `sbom/sbom.cdx.json` in the artifact | [ ] |
| S04 | Security evidence artifact contains a Snyk JSON export | Review `scans/snyk/snyk-report.json` in the artifact | [ ] |
| S05 | Security evidence artifact contains the HTML summary | Review `summary/security-summary.html` in the artifact | [ ] |

**Tested by:** _______________  **Date:** _______________

---

## 7. Rollback

### When to Rollback

- Critical functionality broken
- Security vulnerability discovered
- Data loss or corruption

### Steps

1. Convert GitHub release to draft
2. Ensure previous version is "Latest"
3. Notify team
4. Document incident below

### Incident Report

**Version:** _______________  
**Issue:** _______________________________________________  
**Root Cause:** _______________________________________________  
**Corrective Action:** _______________________________________________  
**Completed by:** _______________  **Date:** _______________

---

## 8. Release Notes Template

```markdown
## v[VERSION] - [DATE]

### Changes
- [Change 1]
- [Change 2]

### Fixes
- [Fix 1]

### Security
- Dependencies updated

### Known Issues
- [If any]
```

---

## 9. Evidence Retention

Evidence is automatically retained:

| Evidence | Location | Retention |
|----------|----------|-----------|
| Workflow logs | GitHub Actions | 90 days (GitHub default) |
| Security evidence artifact | Actions artifacts | 365 days (configured) |
| Release assets | GitHub Releases | Permanent |
| Git tags/commits | Repository | Permanent |

For audits requiring longer retention, download artifacts to secure storage.

---

## 10. Handling Failures

### npm audit fails (critical/high vulnerabilities)

1. Review `scans/npm/audit-report.txt` in the security evidence artifact
2. Options:
   - Run `npm audit fix` locally, commit, re-run workflow
   - If unfixable, assess risk and document exception
   - Delay release until fix available

### Snyk export fails

1. Review `scans/snyk/snyk-export-error.txt` in the security evidence artifact
2. Confirm that:
   - `SNYK_TOKEN` is configured for the repository or organization
   - the Snyk CLI setup step completed successfully
   - the desktop dependency scan can run from the repository root
3. Fix the export issue, then re-run the workflow

### SBOM generation fails

1. Review the `Generate SBOM` step log in the workflow run
2. Confirm `npm install` completed successfully and `package-lock.json` was regenerated
3. Validate that the generated file is a CycloneDX JSON document
4. Fix the dependency or generator issue, then re-run the workflow

### Build fails

1. Check workflow logs for error
2. Fix issue in codebase
3. Delete the tag: `git push --delete origin v{VERSION}`
4. Re-run prepare-release workflow

### Submodule ref not found

1. Verify the drawio tag/ref exists in the drawio repository
2. Use `drawio_ref` input to specify correct ref

---

## Revision History

| Version | Date       | Author      | Changes |
|---------|------------|-------------|---------|
| 1.4     | 2026.04.01 | N Castro    | Add HTML security summary generation to the security evidence artifact |
| 1.3     | 2026.04.01 | N Castro    | Add Snyk JSON export and post-upload enforcement to prepare-release |
| 1.2     | 2026.03.25 | N Castro    | Add mandatory CycloneDX SBOM generation to prepare-release |
| 1.1     | 2026.03.25 | N Castro    | Update security evidence artifact structure and packaging |
| 1.0     | 2026.01.02 | D Benson    | Initial release |
