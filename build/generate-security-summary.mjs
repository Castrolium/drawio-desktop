import {mkdir, readFile, stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';

import {
	normalizeRelativePath,
	requiredAlternativeArtifactFiles,
	requiredArtifactFiles,
	securitySummaryFallbackMarker,
	securitySummaryRelativePath,
	securitySummaryStatuses,
	snykReportStatuses
} from './security-evidence-contract.mjs';

const summaryDirectory = path.posix.dirname(securitySummaryRelativePath);
const snykEvidenceGroup = requiredAlternativeArtifactFiles[0];

const evidenceLabels = new Map([
	['release-notes.md', 'Release notes'],
	['audit-results.json', 'npm audit results (JSON)'],
	['audit-report.txt', 'npm audit report (text)'],
	['outdated-report.txt', 'npm outdated report'],
	['sbom.cdx.json', 'CycloneDX SBOM'],
	['snyk-report.json', 'Snyk report (JSON)'],
	['snyk-export-error.txt', 'Snyk export diagnostics']
]);

function ensureNumber(value)
{
	return Number.isFinite(value) ? value : 0;
}

function escapeHtml(value)
{
	return String(value)
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;')
		.replaceAll("'", '&#39;');
}

function pluralize(count, singular, plural = `${singular}s`)
{
	return `${count} ${count === 1 ? singular : plural}`;
}

function formatRepositoryUrl(repository)
{
	if (!repository || typeof repository !== 'string')
	{
		return null;
	}

	if (repository.startsWith('git@github.com:'))
	{
		return `https://github.com/${repository.slice('git@github.com:'.length).replace(/\.git$/, '')}`;
	}

	if (repository.startsWith('git+https://'))
	{
		return repository.slice('git+'.length).replace(/\.git$/, '');
	}

	if (repository.startsWith('https://') || repository.startsWith('http://'))
	{
		return repository.replace(/\.git$/, '');
	}

	return repository;
}

function getRepositoryFromPackageJson(packageJson)
{
	const repository = packageJson?.repository;

	if (typeof repository === 'string')
	{
		return formatRepositoryUrl(repository);
	}

	if (repository && typeof repository.url === 'string')
	{
		return formatRepositoryUrl(repository.url);
	}

	return null;
}

function getRunUrl(repository, runUrl, runId)
{
	if (runUrl)
	{
		return runUrl;
	}

	if (!repository || !runId || !repository.startsWith('http'))
	{
		return null;
	}

	return `${repository.replace(/\/$/, '')}/actions/runs/${runId}`;
}

async function tryReadJsonFile(filePath)
{
	try
	{
		return JSON.parse(await readFile(filePath, 'utf8'));
	}
	catch (e)
	{
		return null;
	}
}

async function assertFileExists(filePath, sourceName)
{
	let fileStat = null;

	try
	{
		fileStat = await stat(filePath);
	}
	catch (e)
	{
		throw new Error(`Missing required evidence file: ${sourceName}`);
	}

	if (!fileStat.isFile())
	{
		throw new Error(`Required evidence path is not a file: ${sourceName}`);
	}
}

async function readRequiredTextFile(filePath, sourceName)
{
	await assertFileExists(filePath, sourceName);
	return readFile(filePath, 'utf8');
}

async function parseRequiredJsonFile(filePath, sourceName)
{
	await assertFileExists(filePath, sourceName);

	try
	{
		return JSON.parse(await readFile(filePath, 'utf8'));
	}
	catch (e)
	{
		throw new Error(`Invalid JSON in required evidence file: ${sourceName}`);
	}
}

async function resolveMetadata(options, workspaceDir)
{
	const packageJson = await tryReadJsonFile(path.join(workspaceDir, 'package.json'));
	const packageLockJson = await tryReadJsonFile(path.join(workspaceDir, 'package-lock.json'));
	const repository = formatRepositoryUrl(options.repository || getRepositoryFromPackageJson(packageJson));

	return {
		version: options.version || packageJson?.version || null,
		repository,
		workflowName: options.workflowName || null,
		runId: options.runId || null,
		runUrl: getRunUrl(repository, options.runUrl || null, options.runId || null),
		gitRef: options.gitRef || null,
		gitCommit: options.gitCommit || null,
		drawioRef: options.drawioRef || null,
		drawioCommit: options.drawioCommit || null,
		nodeVersion: options.nodeVersion || process.version || null,
		npmVersion: options.npmVersion || null,
		electronVersion: options.electronVersion || packageLockJson?.packages?.['node_modules/electron']?.version || null,
		generatedAt: options.generatedAt || new Date().toISOString()
	};
}

function extractAuditCounts(auditResults)
{
	const vulnerabilities = auditResults?.metadata?.vulnerabilities || {};

	return {
		critical: ensureNumber(vulnerabilities.critical),
		high: ensureNumber(vulnerabilities.high),
		moderate: ensureNumber(vulnerabilities.moderate),
		low: ensureNumber(vulnerabilities.low)
	};
}

function validateSbomJson(sbomJson)
{
	if (sbomJson?.bomFormat !== 'CycloneDX')
	{
		throw new Error('Invalid SBOM format in required evidence file: sbom.cdx.json');
	}
}

function extractSbomFacts(sbomJson)
{
	return {
		format: sbomJson?.bomFormat || 'Unknown',
		specVersion: sbomJson?.specVersion || 'unknown',
		componentCount: Array.isArray(sbomJson?.components) ? sbomJson.components.length : 0,
		primaryComponentName: sbomJson?.metadata?.component?.name || null,
		primaryComponentVersion: sbomJson?.metadata?.component?.version || null
	};
}

async function resolveSnykEvidence(workspaceDir)
{
	const availableCandidates = [];

	for (const candidate of snykEvidenceGroup.candidates)
	{
		const candidatePath = path.join(workspaceDir, candidate.source);

		try
		{
			const candidateStat = await stat(candidatePath);

			if (candidateStat.isFile())
			{
				availableCandidates.push(candidate);
			}
		}
		catch (e)
		{
			// Ignore missing candidate files here and validate the final selection below.
		}
	}

	if (availableCandidates.length === 0)
	{
		throw new Error(`Missing required ${snykEvidenceGroup.description} file: expected one of ${snykEvidenceGroup.candidates.map((candidate) => candidate.source).join(', ')}`);
	}

	if (availableCandidates.length > 1)
	{
		throw new Error(`Conflicting ${snykEvidenceGroup.description} files: expected only one of ${snykEvidenceGroup.candidates.map((candidate) => candidate.source).join(', ')}`);
	}

	return availableCandidates[0];
}

function countFindingsBySeverity(vulnerabilities)
{
	const counts = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0
	};

	for (const vulnerability of vulnerabilities || [])
	{
		const severity = typeof vulnerability?.severity === 'string' ? vulnerability.severity.toLowerCase() : '';

		if (Object.hasOwn(counts, severity))
		{
			counts[severity] += 1;
		}
	}

	return counts;
}

async function readSnykSummary(workspaceDir, selectedCandidate)
{
	if (selectedCandidate.source === 'snyk-report.json')
	{
		const reportJson = await parseRequiredJsonFile(path.join(workspaceDir, selectedCandidate.source), selectedCandidate.source);
		const vulnerabilities = Array.isArray(reportJson?.vulnerabilities) ? reportJson.vulnerabilities : [];
		const counts = countFindingsBySeverity(vulnerabilities);
		const findingsTotal = vulnerabilities.length;

		return {
			fileLabel: evidenceLabels.get(selectedCandidate.source),
			filePath: selectedCandidate.destination,
			reportStatus: findingsTotal > 0 ? snykReportStatuses.findingsDetected : snykReportStatuses.noFindings,
			findingsTotal,
			counts,
			errorDetails: null
		};
	}

	const errorDetails = (await readRequiredTextFile(path.join(workspaceDir, selectedCandidate.source), selectedCandidate.source)).trim();

	return {
		fileLabel: evidenceLabels.get(selectedCandidate.source),
		filePath: selectedCandidate.destination,
		reportStatus: snykReportStatuses.exportFailed,
		findingsTotal: 0,
		counts: {
			critical: 0,
			high: 0,
			medium: 0,
			low: 0
		},
		errorDetails
	};
}

export function determineSecuritySummaryStatus(auditCounts, snykSummary)
{
	if (auditCounts.critical > 0 || auditCounts.high > 0 || snykSummary.reportStatus === snykReportStatuses.exportFailed)
	{
		return securitySummaryStatuses.blocked;
	}

	if (snykSummary.findingsTotal > 0)
	{
		return securitySummaryStatuses.reviewRequired;
	}

	return securitySummaryStatuses.ready;
}

function buildGateReasons(status, auditCounts, snykSummary)
{
	const reasons = [];

	if (auditCounts.critical > 0 || auditCounts.high > 0)
	{
		reasons.push(`npm audit reported ${auditCounts.critical} critical and ${auditCounts.high} high vulnerabilities. Critical or high npm findings block the release.`);
	}

	if (snykSummary.reportStatus === snykReportStatuses.exportFailed)
	{
		reasons.push('The Snyk export failed before a usable report could be produced. Review the diagnostics file before releasing.');
	}
	else if (snykSummary.findingsTotal > 0)
	{
		reasons.push(`Snyk reported ${pluralize(snykSummary.findingsTotal, 'finding')}. The release is not blocked by the current workflow, but a reviewer must assess the report.`);
	}

	if (auditCounts.moderate > 0 || auditCounts.low > 0)
	{
		reasons.push(`npm audit also recorded ${auditCounts.moderate} moderate and ${auditCounts.low} low findings for follow-up.`);
	}

	if (status === securitySummaryStatuses.ready)
	{
		reasons.push('No blocking security gate conditions were detected from npm audit or the Snyk export.');
	}

	return reasons;
}

function buildEvidenceInventory(selectedSnykCandidate)
{
	const requiredInventory = requiredArtifactFiles
		.filter((file) => file.destination !== securitySummaryRelativePath)
		.map((file) => ({
			label: evidenceLabels.get(file.source) || file.source,
			artifactPath: file.destination,
			href: path.posix.relative(summaryDirectory, normalizeRelativePath(file.destination))
		}));

	requiredInventory.push({
		label: evidenceLabels.get(selectedSnykCandidate.source) || selectedSnykCandidate.source,
		artifactPath: selectedSnykCandidate.destination,
		href: path.posix.relative(summaryDirectory, normalizeRelativePath(selectedSnykCandidate.destination))
	});

	return requiredInventory;
}

function extractReleaseNotesHeading(releaseNotes)
{
	for (const line of releaseNotes.split(/\r?\n/u))
	{
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('#'))
		{
			return trimmedLine.replace(/^#+\s*/u, '');
		}
	}

	return null;
}

function formatContextValue(value)
{
	return value === null || value === undefined || value === '' ? '<span class="muted">Not provided</span>' : escapeHtml(String(value));
}

function renderContextRow(label, value)
{
	return `<tr><th scope="row">${escapeHtml(label)}</th><td>${formatContextValue(value)}</td></tr>`;
}

function renderLinkOrText(label, href)
{
	if (!href)
	{
		return '<span class="muted">Not available</span>';
	}

	return `<a href="${escapeHtml(href)}">${escapeHtml(label)}</a>`;
}

function renderInventoryRows(evidenceInventory)
{
	return evidenceInventory.map((item) => `<tr><td>${escapeHtml(item.label)}</td><td><a href="${escapeHtml(item.href)}">${escapeHtml(item.artifactPath)}</a></td></tr>`).join('');
}

function renderSeverityRows(rows)
{
	return rows.map((row) => `<tr><th scope="row">${escapeHtml(row.label)}</th><td>${escapeHtml(String(row.value))}</td></tr>`).join('');
}

function renderPageStyles()
{
	return `
      :root {
        color-scheme: light;
        --bg: #f4f7fb;
        --panel: #ffffff;
        --border: #d7dee8;
        --text: #142033;
        --muted: #62708a;
        --ready: #196c2e;
        --ready-bg: #e7f6ea;
        --review: #9a6200;
        --review-bg: #fff4d8;
        --blocked: #a12622;
        --blocked-bg: #fde7e9;
        --shadow: 0 10px 30px rgba(20, 32, 51, 0.08);
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        padding: 32px;
        font-family: "Segoe UI", Arial, sans-serif;
        background: linear-gradient(180deg, #f7f9fc 0%, #eef3f9 100%);
        color: var(--text);
      }

      main {
        max-width: 1080px;
        margin: 0 auto;
      }

      .hero,
      section {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 18px;
        box-shadow: var(--shadow);
        padding: 24px;
      }

      .hero {
        margin-bottom: 20px;
      }

      section + section {
        margin-top: 20px;
      }

      .eyebrow {
        margin: 0 0 8px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
        font-size: 12px;
        font-weight: 700;
      }

      h1,
      h2 {
        margin-top: 0;
      }

      h1 {
        margin-bottom: 12px;
        font-size: 32px;
      }

      h2 {
        margin-bottom: 12px;
        font-size: 22px;
      }

      p,
      li,
      td,
      th {
        line-height: 1.5;
      }

      .status-line {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
        margin-bottom: 12px;
      }

      .status-pill {
        display: inline-flex;
        align-items: center;
        border-radius: 999px;
        padding: 6px 12px;
        font-weight: 700;
        text-transform: lowercase;
      }

      .status-ready {
        color: var(--ready);
        background: var(--ready-bg);
      }

      .status-review-required {
        color: var(--review);
        background: var(--review-bg);
      }

      .status-blocked {
        color: var(--blocked);
        background: var(--blocked-bg);
      }

      .muted {
        color: var(--muted);
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
        gap: 20px;
      }

      table {
        width: 100%;
        border-collapse: collapse;
      }

      th,
      td {
        text-align: left;
        vertical-align: top;
        border-top: 1px solid var(--border);
        padding: 10px 0;
      }

      th {
        width: 34%;
        color: var(--muted);
        font-weight: 600;
      }

      a {
        color: #0b61d8;
        text-decoration: none;
      }

      a:hover,
      a:focus {
        text-decoration: underline;
      }

      pre {
        margin: 16px 0 0;
        padding: 16px;
        overflow-x: auto;
        white-space: pre-wrap;
        background: #101828;
        border-radius: 12px;
        color: #e7edf6;
      }

      ul {
        margin: 0;
        padding-left: 20px;
      }

      @media (max-width: 720px) {
        body {
          padding: 16px;
        }

        .hero,
        section {
          padding: 18px;
        }

        h1 {
          font-size: 28px;
        }

        th {
          width: 42%;
        }
      }`;
}

export function renderSecuritySummaryHtml(model)
{
	const statusLead = {
		[securitySummaryStatuses.ready]: 'The release evidence passed the current automated gate checks.',
		[securitySummaryStatuses.reviewRequired]: 'The release evidence is available, but a reviewer must assess the reported Snyk findings.',
		[securitySummaryStatuses.blocked]: 'The release evidence indicates a blocking issue that must be resolved before releasing.'
	}[model.status];
	const releaseLabel = model.metadata.version ? `Release ${model.metadata.version}` : 'Unversioned release';
	const releaseNotesHeading = model.releaseNotesHeading || 'No heading detected in release-notes.md';
	const reviewNoteItems = model.gateReasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('');
	const snykDetails = model.snyk.errorDetails ? `<pre>${escapeHtml(model.snyk.errorDetails)}</pre>` : '';
	const primaryComponent = [model.sbom.primaryComponentName, model.sbom.primaryComponentVersion].filter(Boolean).join(' ');

	return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Summary - ${escapeHtml(releaseLabel)}</title>
    <style>${renderPageStyles()}
    </style>
  </head>
  <body>
    <main>
      <header class="hero">
        <p class="eyebrow">Security Evidence Pack</p>
        <h1>Security Summary</h1>
        <div class="status-line">
          <span class="status-pill status-${escapeHtml(model.status)}">${escapeHtml(model.status)}</span>
          <span>${escapeHtml(releaseLabel)}</span>
        </div>
        <p>${escapeHtml(statusLead)}</p>
        <p class="muted">Release notes heading: ${escapeHtml(releaseNotesHeading)}</p>
      </header>

      <section>
        <h2>Overall Status and Review Notes</h2>
        <ul>
          ${reviewNoteItems}
        </ul>
      </section>

      <section class="grid">
        <div>
          <h2>Release and Run Context</h2>
          <table>
            <tbody>
              ${renderContextRow('Version', model.metadata.version)}
              <tr><th scope="row">Repository</th><td>${renderLinkOrText(model.metadata.repository, model.metadata.repository)}</td></tr>
              ${renderContextRow('Workflow', model.metadata.workflowName)}
              ${renderContextRow('Run ID', model.metadata.runId)}
              <tr><th scope="row">Run URL</th><td>${renderLinkOrText(model.metadata.runUrl, model.metadata.runUrl)}</td></tr>
              ${renderContextRow('Git ref', model.metadata.gitRef)}
              ${renderContextRow('Git commit', model.metadata.gitCommit)}
              ${renderContextRow('drawio ref', model.metadata.drawioRef)}
              ${renderContextRow('drawio commit', model.metadata.drawioCommit)}
              ${renderContextRow('Generated at', model.metadata.generatedAt)}
            </tbody>
          </table>
        </div>

        <div>
          <h2>Tooling</h2>
          <table>
            <tbody>
              ${renderContextRow('Node.js', model.metadata.nodeVersion)}
              ${renderContextRow('npm', model.metadata.npmVersion)}
              ${renderContextRow('Electron', model.metadata.electronVersion)}
              ${renderContextRow('Summary file', securitySummaryRelativePath)}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2>Evidence Inventory</h2>
        <table>
          <thead>
            <tr>
              <th scope="col">Evidence</th>
              <th scope="col">Artifact path</th>
            </tr>
          </thead>
          <tbody>
            ${renderInventoryRows(model.evidenceInventory)}
          </tbody>
        </table>
      </section>

      <section class="grid">
        <div>
          <h2>npm Audit</h2>
          <table>
            <tbody>
              ${renderSeverityRows([
		{label: 'Critical', value: model.audit.critical},
		{label: 'High', value: model.audit.high},
		{label: 'Moderate', value: model.audit.moderate},
		{label: 'Low', value: model.audit.low}
	])}
            </tbody>
          </table>
          <p class="muted">Critical or high npm audit findings block the release gate.</p>
        </div>

        <div>
          <h2>Snyk</h2>
          <table>
            <tbody>
              ${renderContextRow('Report status', model.snyk.reportStatus)}
              ${renderContextRow('Evidence file', model.snyk.filePath)}
              ${renderContextRow('Findings total', model.snyk.findingsTotal)}
              ${renderSeverityRows([
		{label: 'Critical', value: model.snyk.counts.critical},
		{label: 'High', value: model.snyk.counts.high},
		{label: 'Medium', value: model.snyk.counts.medium},
		{label: 'Low', value: model.snyk.counts.low}
	])}
            </tbody>
          </table>
          ${snykDetails}
        </div>
      </section>

      <section>
        <h2>SBOM Facts</h2>
        <table>
          <tbody>
            ${renderContextRow('Format', model.sbom.format)}
            ${renderContextRow('Spec version', model.sbom.specVersion)}
            ${renderContextRow('Components', model.sbom.componentCount)}
            ${renderContextRow('Primary component', primaryComponent || null)}
            ${renderContextRow('Artifact path', 'sbom/sbom.cdx.json')}
          </tbody>
        </table>
      </section>
    </main>
  </body>
</html>
`;
}

export function renderFallbackSecuritySummaryHtml(model)
{
	const releaseLabel = model.version ? `Release ${model.version}` : 'Unversioned release';
	const reviewNotes = (model.reasons?.length ? model.reasons : [
		'The generated security summary was unavailable during packaging.',
		'Review the packaged raw evidence and workflow logs before retrying the release.'
	]).map((reason) => `<li>${escapeHtml(reason)}</li>`).join('');

	return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Summary - Fallback for ${escapeHtml(releaseLabel)}</title>
    <style>${renderPageStyles()}
    </style>
  </head>
  <body ${securitySummaryFallbackMarker}>
    <main>
      <header class="hero">
        <p class="eyebrow">Security Evidence Pack</p>
        <h1>Fallback Security Summary</h1>
        <div class="status-line">
          <span class="status-pill status-${securitySummaryStatuses.blocked}">${securitySummaryStatuses.blocked}</span>
          <span>${escapeHtml(releaseLabel)}</span>
        </div>
        <p>This troubleshooting view was staged so the packaged evidence remains available even though the validated HTML summary was unavailable or incomplete.</p>
        <p class="muted">Artifact: ${escapeHtml(model.artifactName || 'security-evidence-pack')}</p>
      </header>

      <section>
        <h2>What Needs Attention</h2>
        <ul>
          ${reviewNotes}
        </ul>
      </section>

      <section class="grid">
        <div>
          <h2>Packaging Context</h2>
          <table>
            <tbody>
              ${renderContextRow('Version', model.version || null)}
              ${renderContextRow('Artifact name', model.artifactName || null)}
              ${renderContextRow('Generated at', model.generatedAt || null)}
              ${renderContextRow('Summary mode', 'fallback')}
            </tbody>
          </table>
        </div>

        <div>
          <h2>Next Step</h2>
          <p class="muted">Inspect the staged files below, then review the workflow logs to fix the missing or invalid evidence before re-running the release preparation.</p>
        </div>
      </section>

      <section>
        <h2>Staged Evidence</h2>
        <table>
          <thead>
            <tr>
              <th scope="col">Evidence</th>
              <th scope="col">Artifact path</th>
            </tr>
          </thead>
          <tbody>
            ${renderInventoryRows(model.evidenceInventory || [])}
          </tbody>
        </table>
      </section>
    </main>
  </body>
</html>
`;
}

export async function collectSecuritySummaryData(options = {})
{
	const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
	const releaseNotes = await readRequiredTextFile(path.join(workspaceDir, 'release-notes.md'), 'release-notes.md');
	await readRequiredTextFile(path.join(workspaceDir, 'audit-report.txt'), 'audit-report.txt');
	await readRequiredTextFile(path.join(workspaceDir, 'outdated-report.txt'), 'outdated-report.txt');

	const auditResults = await parseRequiredJsonFile(path.join(workspaceDir, 'audit-results.json'), 'audit-results.json');
	const sbomJson = await parseRequiredJsonFile(path.join(workspaceDir, 'sbom.cdx.json'), 'sbom.cdx.json');
	validateSbomJson(sbomJson);

	const selectedSnykCandidate = await resolveSnykEvidence(workspaceDir);
	const metadata = await resolveMetadata(options, workspaceDir);
	const auditCounts = extractAuditCounts(auditResults);
	const snykSummary = await readSnykSummary(workspaceDir, selectedSnykCandidate);
	const status = determineSecuritySummaryStatus(auditCounts, snykSummary);

	return {
		workspaceDir,
		metadata,
		releaseNotesHeading: extractReleaseNotesHeading(releaseNotes),
		status,
		gateReasons: buildGateReasons(status, auditCounts, snykSummary),
		evidenceInventory: buildEvidenceInventory(selectedSnykCandidate),
		audit: auditCounts,
		snyk: snykSummary,
		sbom: extractSbomFacts(sbomJson)
	};
}

export async function generateSecuritySummary(options = {})
{
	const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
	const outputPath = path.resolve(options.outputPath || path.join(workspaceDir, securitySummaryRelativePath));
	const model = await collectSecuritySummaryData({
		...options,
		workspaceDir
	});
	const html = renderSecuritySummaryHtml(model);

	await mkdir(path.dirname(outputPath), {recursive: true});
	await writeFile(outputPath, html, 'utf8');

	return {
		outputPath,
		status: model.status,
		gateReasons: model.gateReasons,
		evidenceInventory: model.evidenceInventory
	};
}

export function parseCliOptions(argv = process.argv.slice(2))
{
	const {values} = parseArgs({
		args: argv,
		options: {
			version: {type: 'string'},
			repository: {type: 'string'},
			'workflow-name': {type: 'string'},
			'run-id': {type: 'string'},
			'run-url': {type: 'string'},
			'git-ref': {type: 'string'},
			'git-commit': {type: 'string'},
			'drawio-ref': {type: 'string'},
			'drawio-commit': {type: 'string'},
			'node-version': {type: 'string'},
			'npm-version': {type: 'string'},
			'electron-version': {type: 'string'},
			'generated-at': {type: 'string'},
			'workspace-dir': {type: 'string'},
			'output-path': {type: 'string'}
		},
		strict: true
	});

	return {
		version: values.version,
		repository: values.repository,
		workflowName: values['workflow-name'],
		runId: values['run-id'],
		runUrl: values['run-url'],
		gitRef: values['git-ref'],
		gitCommit: values['git-commit'],
		drawioRef: values['drawio-ref'],
		drawioCommit: values['drawio-commit'],
		nodeVersion: values['node-version'],
		npmVersion: values['npm-version'],
		electronVersion: values['electron-version'],
		generatedAt: values['generated-at'],
		workspaceDir: values['workspace-dir'],
		outputPath: values['output-path']
	};
}

export async function main(argv = process.argv.slice(2))
{
	const result = await generateSecuritySummary(parseCliOptions(argv));

	console.log(`Generated security summary: ${normalizeRelativePath(result.outputPath)}`);
	console.log(`Status: ${result.status}`);
}

const entryPoint = process.argv[1] ? path.resolve(process.argv[1]) : '';

if (entryPoint === fileURLToPath(import.meta.url))
{
	main().catch((e) =>
	{
		console.error(e.message);
		process.exitCode = 1;
	});
}
