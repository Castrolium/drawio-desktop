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
	const evidenceDescriptors = new Map([
		['release-notes.md', {
			check: 'Release context',
			reviewUse: 'Confirms the release scope and human-readable change context.'
		}],
		['audit-results.json', {
			check: 'npm audit',
			reviewUse: 'Provides the machine-readable vulnerability counts used for the release gate.'
		}],
		['audit-report.txt', {
			check: 'npm audit',
			reviewUse: 'Gives reviewers a readable text view of the npm audit result.'
		}],
		['outdated-report.txt', {
			check: 'Dependency freshness',
			reviewUse: 'Highlights outdated dependencies that may need follow-up after the release.'
		}],
		['sbom.cdx.json', {
			check: 'SBOM',
			reviewUse: 'Captures the CycloneDX component inventory for the packaged application.'
		}],
		['snyk-report.json', {
			check: 'Snyk',
			reviewUse: 'Contains the machine-readable Snyk findings that may require manual review.'
		}],
		['snyk-export-error.txt', {
			check: 'Snyk',
			reviewUse: 'Captures the Snyk export failure details that must be resolved before release.'
		}]
	]);
	const requiredInventory = requiredArtifactFiles
		.filter((file) => file.destination !== securitySummaryRelativePath)
		.map((file) =>
		{
			const descriptor = evidenceDescriptors.get(file.source) || {
				check: 'Supporting evidence',
				reviewUse: 'Provides supporting release evidence for reviewer follow-up.'
			};

			return {
				label: evidenceLabels.get(file.source) || file.source,
				artifactPath: file.destination,
				href: path.posix.relative(summaryDirectory, normalizeRelativePath(file.destination)),
				check: descriptor.check,
				reviewUse: descriptor.reviewUse
			};
		});
	const selectedSnykDescriptor = evidenceDescriptors.get(selectedSnykCandidate.source) || {
		check: 'Snyk',
		reviewUse: 'Provides Snyk evidence for reviewer follow-up.'
	};

	requiredInventory.push({
		label: evidenceLabels.get(selectedSnykCandidate.source) || selectedSnykCandidate.source,
		artifactPath: selectedSnykCandidate.destination,
		href: path.posix.relative(summaryDirectory, normalizeRelativePath(selectedSnykCandidate.destination)),
		check: selectedSnykDescriptor.check,
		reviewUse: selectedSnykDescriptor.reviewUse
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

function formatStatusLabel(status)
{
	return String(status).replaceAll('-', ' ');
}

function renderSeverityRows(rows)
{
	return rows.map((row) => `<tr><th scope="row">${escapeHtml(row.label)}</th><td>${escapeHtml(String(row.value))}</td></tr>`).join('');
}

function renderStatusPill(status)
{
	return `<span class="status-pill status-${escapeHtml(status)}">${escapeHtml(formatStatusLabel(status))}</span>`;
}

function getStatusPresentation(status)
{
	return {
		[securitySummaryStatuses.ready]: {
			title: 'Ready for release review',
			lead: 'Automated gate checks passed. Reviewers can use the linked evidence to confirm the release context and any follow-up items.',
			nextStep: 'Confirm the linked raw evidence and continue with the normal release approval flow.'
		},
		[securitySummaryStatuses.reviewRequired]: {
			title: 'Reviewer decision needed',
			lead: 'The evidence pack is complete, but Snyk findings still need a human decision before the release can proceed.',
			nextStep: 'Review the linked Snyk report, record the decision, and only then continue with release approval.'
		},
		[securitySummaryStatuses.blocked]: {
			title: 'Release blocked',
			lead: 'A blocking security or evidence issue must be resolved before the release can proceed.',
			nextStep: 'Do not release until the blocking issue is fixed and the evidence pack has been regenerated.'
		}
	}[status];
}

function buildReviewerActions(status, auditCounts, snykSummary)
{
	if (status === securitySummaryStatuses.ready)
	{
		return [
			'Confirm that the linked evidence files match the release candidate being reviewed.',
			'Use the npm audit, dependency freshness, and SBOM sections below for any follow-up context.',
			'Continue with the normal release approval flow once the evidence has been checked.'
		];
	}

	if (status === securitySummaryStatuses.reviewRequired)
	{
		return [
			`Review ${pluralize(snykSummary.findingsTotal, 'Snyk finding')} in the linked report before approving the release.`,
			'Record the reviewer decision or follow-up ticket together with the release approval.',
			'If the findings are not acceptable, resolve them and regenerate the evidence pack before releasing.'
		];
	}

	const actions = [
		'Do not publish this release while the summary status remains blocked.'
	];

	if (auditCounts.critical > 0 || auditCounts.high > 0)
	{
		actions.push(`Resolve the npm audit gate: ${auditCounts.critical} critical and ${auditCounts.high} high findings are currently blocking the release.`);
	}

	if (snykSummary.reportStatus === snykReportStatuses.exportFailed)
	{
		actions.push('Fix the Snyk export failure, regenerate the evidence pack, and re-run the release validation.');
	}

	actions.push('After remediation, regenerate the HTML summary so the linked evidence and gate result stay aligned.');
	return actions;
}

function buildRelevantFindingsSummary(model)
{
	if (model.status === securitySummaryStatuses.ready)
	{
		const followUpSummary = model.audit.moderate > 0 || model.audit.low > 0
			? `No blocking gate findings. ${model.audit.moderate} moderate and ${model.audit.low} low npm audit findings remain available for follow-up.`
			: 'No blocking gate findings were reported by npm audit or Snyk.';

		return followUpSummary;
	}

	if (model.status === securitySummaryStatuses.reviewRequired)
	{
		return `Manual review is required because Snyk reported ${pluralize(model.snyk.findingsTotal, 'finding')}.`;
	}

	if (model.snyk.reportStatus === snykReportStatuses.exportFailed)
	{
		return 'The release is blocked because the Snyk export failed before a usable report was produced.';
	}

	return `The release is blocked because npm audit reported ${model.audit.critical} critical and ${model.audit.high} high findings.`;
}

function buildExecutiveSummaryCards(model)
{
	const releaseLabel = model.metadata.version ? `Release ${model.metadata.version}` : 'Unversioned release';

	return [
		{
			label: 'Version Under Review',
			value: releaseLabel
		},
		{
			label: 'Checks Executed',
			value: 'npm audit, npm outdated snapshot, Snyk export, and CycloneDX SBOM generation'
		},
		{
			label: 'Relevant Findings',
			value: buildRelevantFindingsSummary(model)
		},
		{
			label: 'Raw Evidence',
			value: `${model.evidenceInventory.length} linked evidence files are listed below for direct inspection.`
		}
	];
}

function findEvidenceItems(evidenceInventory, check)
{
	return evidenceInventory.filter((item) => item.check === check);
}

function buildAuditSummary(auditCounts)
{
	if (auditCounts.critical > 0 || auditCounts.high > 0)
	{
		return `Blocking gate result: ${auditCounts.critical} critical and ${auditCounts.high} high npm audit findings were reported.`;
	}

	if (auditCounts.moderate > 0 || auditCounts.low > 0)
	{
		return `No blocking npm audit findings were reported. ${auditCounts.moderate} moderate and ${auditCounts.low} low findings remain visible for follow-up.`;
	}

	return 'No npm audit findings were reported.';
}

function buildSnykSummary(snykSummary)
{
	if (snykSummary.reportStatus === snykReportStatuses.exportFailed)
	{
		return 'Blocking gate result: the Snyk export failed before a usable report could be packaged.';
	}

	if (snykSummary.findingsTotal > 0)
	{
		return `Reviewer decision required: Snyk reported ${pluralize(snykSummary.findingsTotal, 'finding')}.`;
	}

	return 'No Snyk findings were reported in the exported evidence.';
}

function buildCheckSummaries(model)
{
	const sbomPrimaryComponent = [model.sbom.primaryComponentName, model.sbom.primaryComponentVersion].filter(Boolean).join(' ');

	return [
		{
			title: 'npm Audit',
			status: model.audit.critical > 0 || model.audit.high > 0 ? securitySummaryStatuses.blocked : securitySummaryStatuses.ready,
			summary: buildAuditSummary(model.audit),
			reviewerNote: 'Critical or high npm audit findings block the release gate. Use the text report for readable context and the JSON file for exact counts.',
			evidenceItems: findEvidenceItems(model.evidenceInventory, 'npm audit'),
			detailRows: [
				{label: 'Critical', value: model.audit.critical},
				{label: 'High', value: model.audit.high},
				{label: 'Moderate', value: model.audit.moderate},
				{label: 'Low', value: model.audit.low}
			]
		},
		{
			title: 'Snyk',
			status: model.snyk.reportStatus === snykReportStatuses.exportFailed
				? securitySummaryStatuses.blocked
				: model.snyk.findingsTotal > 0
					? securitySummaryStatuses.reviewRequired
					: securitySummaryStatuses.ready,
			summary: buildSnykSummary(model.snyk),
			reviewerNote: model.snyk.reportStatus === snykReportStatuses.exportFailed
				? 'Fix the Snyk export problem before release so the evidence pack contains a usable report.'
				: model.snyk.findingsTotal > 0
					? 'A reviewer must assess the linked Snyk findings before the release can proceed.'
					: 'No reviewer escalation is required from the Snyk export when no findings are present.',
			evidenceItems: findEvidenceItems(model.evidenceInventory, 'Snyk'),
			detailRows: [
				{label: 'Report status', value: model.snyk.reportStatus},
				{label: 'Findings total', value: model.snyk.findingsTotal},
				{label: 'Critical', value: model.snyk.counts.critical},
				{label: 'High', value: model.snyk.counts.high},
				{label: 'Medium', value: model.snyk.counts.medium},
				{label: 'Low', value: model.snyk.counts.low}
			],
			diagnostics: model.snyk.errorDetails
		},
		{
			title: 'SBOM',
			status: securitySummaryStatuses.ready,
			summary: `CycloneDX SBOM validated with ${pluralize(model.sbom.componentCount, 'component')}.`,
			reviewerNote: 'Use the SBOM to confirm the packaged component inventory and the primary application metadata.',
			evidenceItems: findEvidenceItems(model.evidenceInventory, 'SBOM'),
			detailRows: [
				{label: 'Format', value: model.sbom.format},
				{label: 'Spec version', value: model.sbom.specVersion},
				{label: 'Components', value: model.sbom.componentCount},
				{label: 'Primary component', value: sbomPrimaryComponent || 'Not provided'}
			]
		}
	];
}

function renderExecutiveSummaryCards(cards)
{
	return cards.map((card) => `
          <article class="summary-card">
            <p class="card-label">${escapeHtml(card.label)}</p>
            <p class="card-value">${escapeHtml(card.value)}</p>
          </article>`).join('');
}

function renderActionItems(items)
{
	return items.map((item) => `<li>${escapeHtml(item)}</li>`).join('');
}

function renderEvidenceLinks(items)
{
	if (!items?.length)
	{
		return '<span class="muted">Not available</span>';
	}

	return items.map((item) => `<a href="${escapeHtml(item.href)}">${escapeHtml(item.artifactPath)}</a>`).join('<br>');
}

function renderDetailedInventoryRows(evidenceInventory)
{
	return evidenceInventory.map((item) => `<tr><td>${escapeHtml(item.check)}</td><td>${escapeHtml(item.label)}</td><td>${escapeHtml(item.reviewUse)}</td><td><a href="${escapeHtml(item.href)}">${escapeHtml(item.artifactPath)}</a></td></tr>`).join('');
}

function renderSimpleInventoryRows(evidenceInventory)
{
	return evidenceInventory.map((item) => `<tr><td>${escapeHtml(item.label)}</td><td><a href="${escapeHtml(item.href)}">${escapeHtml(item.artifactPath)}</a></td></tr>`).join('');
}

function renderCheckCards(checkSummaries)
{
	return checkSummaries.map((check) => {
		const diagnostics = check.diagnostics ? `<pre>${escapeHtml(check.diagnostics)}</pre>` : '';

		return `
          <article class="check-card">
            <div class="section-heading">
              <h3>${escapeHtml(check.title)}</h3>
              ${renderStatusPill(check.status)}
            </div>
            <p>${escapeHtml(check.summary)}</p>
            <p class="muted"><strong>Reviewer note:</strong> ${escapeHtml(check.reviewerNote)}</p>
            <p class="muted"><strong>Evidence files:</strong><br>${renderEvidenceLinks(check.evidenceItems)}</p>
            <table>
              <tbody>
                ${renderSeverityRows(check.detailRows)}
              </tbody>
            </table>
            ${diagnostics}
          </article>`;
	}).join('');
}

function renderPageStyles()
{
	return `
      :root {
        color-scheme: light;
        --bg: #eef3f9;
        --panel: #ffffff;
        --border: #d7dee8;
        --text: #142033;
        --muted: #62708a;
        --accent: #0b61d8;
        --hero-border: #b9c8db;
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
        background:
          radial-gradient(circle at top left, rgba(11, 97, 216, 0.08), transparent 28%),
          linear-gradient(180deg, #f7f9fc 0%, #eef3f9 100%);
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
        border-top: 6px solid var(--hero-border);
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
      h2,
      h3 {
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

      h3 {
        margin-bottom: 8px;
        font-size: 18px;
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

      .hero-ready {
        --hero-border: #196c2e;
      }

      .hero-review-required {
        --hero-border: #c98900;
      }

      .hero-blocked {
        --hero-border: #a12622;
      }

      .muted {
        color: var(--muted);
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
        gap: 20px;
      }

      .summary-grid,
      .check-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
      }

      .check-grid {
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      }

      .summary-card,
      .check-card,
      .callout {
        background: #f9fbfe;
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 18px;
      }

      .callout {
        margin: 20px 0;
      }

      .card-label {
        margin: 0 0 8px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--muted);
        font-size: 12px;
        font-weight: 700;
      }

      .card-value {
        margin: 0;
        font-size: 18px;
        font-weight: 600;
      }

      .section-heading {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 12px;
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
        color: var(--muted);
        font-weight: 600;
      }

      tbody th {
        width: 34%;
      }

      a {
        color: var(--accent);
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

      strong {
        color: var(--text);
      }

      @media print {
        body {
          padding: 0;
          background: #ffffff;
        }

        main {
          max-width: none;
        }

        .hero,
        section,
        .summary-card,
        .check-card,
        .callout {
          box-shadow: none;
          break-inside: avoid;
        }

        a {
          color: var(--text);
        }
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

        .section-heading {
          flex-direction: column;
        }

        tbody th {
          width: 42%;
        }
      }`;
}

export function renderSecuritySummaryHtml(model)
{
	const statusPresentation = getStatusPresentation(model.status);
	const releaseLabel = model.metadata.version ? `Release ${model.metadata.version}` : 'Unversioned release';
	const releaseNotesHeading = model.releaseNotesHeading || 'No heading detected in release-notes.md';
	const reviewNoteItems = model.gateReasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('');

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
      <header class="hero hero-${escapeHtml(model.status)}">
        <p class="eyebrow">Security Evidence Pack</p>
        <h1>Security Summary</h1>
        <div class="status-line">
          ${renderStatusPill(model.status)}
          <span>${escapeHtml(releaseLabel)}</span>
        </div>
        <h2>${escapeHtml(statusPresentation.title)}</h2>
        <p>${escapeHtml(statusPresentation.lead)}</p>
        <p class="muted">Release notes heading: ${escapeHtml(releaseNotesHeading)}</p>

        <div class="callout">
          <p class="card-label">Reviewer Next Step</p>
          <p class="card-value">${escapeHtml(statusPresentation.nextStep)}</p>
        </div>

        <div class="summary-grid">
          ${renderExecutiveSummaryCards(model.executiveSummaryCards)}
        </div>
      </header>

      <section>
        <h2>Gate Evaluation</h2>
        <ul>
          ${reviewNoteItems}
        </ul>
      </section>

      <section>
        <h2>Reviewer Actions</h2>
        <ul>
          ${renderActionItems(model.reviewerActions)}
        </ul>
      </section>

      <section>
        <h2>Evidence Inventory</h2>
        <p class="muted">Each link points to a raw evidence file inside the packaged artifact so reviewers can verify the summary without hunting through the archive.</p>
        <table>
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Evidence</th>
              <th scope="col">Used for review</th>
              <th scope="col">Artifact path</th>
            </tr>
          </thead>
          <tbody>
            ${renderDetailedInventoryRows(model.evidenceInventory)}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Check Details</h2>
        <div class="check-grid">
          ${renderCheckCards(model.checkSummaries)}
        </div>
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
    </main>
  </body>
</html>
`;
}

export function renderFallbackSecuritySummaryHtml(model)
{
	const releaseLabel = model.version ? `Release ${model.version}` : 'Unversioned release';
	const stagedEvidenceCount = Array.isArray(model.evidenceInventory) ? model.evidenceInventory.length : 0;
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
      <header class="hero hero-${securitySummaryStatuses.blocked}">
        <p class="eyebrow">Security Evidence Pack</p>
        <h1>Fallback Security Summary</h1>
        <div class="status-line">
          ${renderStatusPill(securitySummaryStatuses.blocked)}
          <span>${escapeHtml(releaseLabel)}</span>
        </div>
        <p>This troubleshooting view was staged so the packaged evidence remains available even though the validated HTML summary was unavailable or incomplete.</p>
        <p class="muted">Artifact: ${escapeHtml(model.artifactName || 'security-evidence-pack')}</p>

        <div class="summary-grid">
          ${renderExecutiveSummaryCards([
		{label: 'Summary mode', value: 'Fallback troubleshooting view'},
		{label: 'Artifact', value: model.artifactName || 'security-evidence-pack'},
		{label: 'Available Raw Evidence', value: `${stagedEvidenceCount} linked files were staged for inspection.`},
		{label: 'Immediate Action', value: 'Inspect the staged evidence, review the workflow logs, and regenerate the missing or invalid summary.'}
	])}
        </div>
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
            ${renderSimpleInventoryRows(model.evidenceInventory || [])}
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
	const evidenceInventory = buildEvidenceInventory(selectedSnykCandidate);
	const sbomFacts = extractSbomFacts(sbomJson);

	const model = {
		workspaceDir,
		metadata,
		releaseNotesHeading: extractReleaseNotesHeading(releaseNotes),
		status,
		gateReasons: buildGateReasons(status, auditCounts, snykSummary),
		evidenceInventory,
		audit: auditCounts,
		snyk: snykSummary,
		sbom: sbomFacts
	};

	return {
		...model,
		reviewerActions: buildReviewerActions(status, auditCounts, snykSummary),
		executiveSummaryCards: buildExecutiveSummaryCards(model),
		checkSummaries: buildCheckSummaries(model)
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
