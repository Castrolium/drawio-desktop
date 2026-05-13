# Security Summary PDF Spike

## Scope

This note records a small feasibility spike for an optional PDF version of the Security Summary.

Current MVP decision:
- Keep `summary/security-summary.html` as the only required summary artifact.
- Do not add PDF generation, packaging, or validation to the release workflow yet.

## What Was Checked

- The artifact contract already reserves `optional/security-summary.pdf` as a future path in `build/security-evidence-contract.mjs`.
- The repository already depends on Electron and contains existing PDF export logic in `src/main/electron.js` via `webContents.printToPDF`.
- The Security Summary generator itself is currently a plain Node.js script that renders standalone HTML.

## Feasibility Assessment

Based on the existing Electron runtime and the current summary output, a local HTML-to-PDF prototype looks feasible without changing the artifact contract.

Most likely path:
1. Generate `summary/security-summary.html` with the existing script.
2. Open that file in a minimal Electron window or BrowserWindow helper.
3. Use `webContents.printToPDF` to write an optional `security-summary.pdf`.

Why this path is preferred:
- It reuses runtime capabilities already present in the repository.
- It avoids maintaining a second template beside the HTML summary.
- It keeps HTML as the single source of truth for reviewer-facing content.

## Current Limitation

No local PDF prototype was executed in this workspace because `node` and `npm` are currently not available in the active shell environment.

That means this spike is a static feasibility assessment, not a runtime-validated prototype.

## Recommendation

Keep PDF out of the MVP for now.

Reason:
- HTML already satisfies the current SecProj MVP requirements.
- PDF would add runtime and CI complexity that is not yet justified.
- The cleanest future implementation is to treat PDF as a derived optional export from the generated HTML.

Estimated future effort:
- Local prototype from generated HTML: low to medium effort.
- CI-hardening, artifact integration, and validation: additional follow-up effort and risk.
