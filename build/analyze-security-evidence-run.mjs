import {createHash} from 'node:crypto';
import {readdir, readFile, stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';

import {validatePackagedSecurityEvidence} from './package-security-evidence.mjs';
import {
	getSecurityEvidenceArtifactName,
	normalizeRelativePath,
	requiredAlternativeArtifactFiles,
	requiredArtifactFiles,
	securityEvidenceArtifactPrefix,
	securitySummaryFallbackMarker,
	securitySummaryStatuses,
	snykReportStatuses
} from './security-evidence-contract.mjs';

function decodeHtmlEntities(value)
{
	return String(value)
		.replaceAll('&amp;', '&')
		.replaceAll('&lt;', '<')
		.replaceAll('&gt;', '>')
		.replaceAll('&quot;', '"')
		.replaceAll('&#39;', "'");
}

function stripHtml(value)
{
	return decodeHtmlEntities(String(value).replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim());
}

function uniqueSorted(values)
{
	return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function ensureNumber(value)
{
	return Number.isFinite(value) ? value : 0;
}

function asNullableString(value)
{
	return typeof value === 'string' && value.length > 0 ? value : null;
}

async function exists(filePath)
{
	try
	{
		return (await stat(filePath)).isFile();
	}
	catch (e)
	{
		return false;
	}
}

async function parseJsonFile(filePath)
{
	return JSON.parse(await readFile(filePath, 'utf8'));
}

async function hashFile(filePath)
{
	const contents = await readFile(filePath);
	return createHash('sha256').update(contents).digest('hex');
}

async function collectArtifactInventory(rootDir, prefix = '')
{
	const entries = await readdir(rootDir, {withFileTypes: true});
	const files = [];

	for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name)))
	{
		const absolutePath = path.join(rootDir, entry.name);
		const relativePath = prefix ? path.posix.join(prefix, entry.name) : entry.name;

		if (entry.isDirectory())
		{
			files.push(...await collectArtifactInventory(absolutePath, relativePath));
			continue;
		}

		const fileStat = await stat(absolutePath);
		files.push({
			path: normalizeRelativePath(relativePath),
			size: fileStat.size,
			sha256: await hashFile(absolutePath)
		});
	}

	return files;
}

async function resolveArtifactDirectory(inputPath)
{
	const absolutePath = path.resolve(inputPath);
	const pathStat = await stat(absolutePath);

	if (!pathStat.isDirectory())
	{
		throw new Error(`Artifact path is not a directory: ${absolutePath}`);
	}

	if (path.basename(absolutePath).startsWith(securityEvidenceArtifactPrefix))
	{
		return absolutePath;
	}

	const entries = await readdir(absolutePath, {withFileTypes: true});
	const candidateDirectories = entries
		.filter((entry) => entry.isDirectory() && entry.name.startsWith(securityEvidenceArtifactPrefix))
		.map((entry) => path.join(absolutePath, entry.name));

	if (candidateDirectories.length === 1)
	{
		return candidateDirectories[0];
	}

	if (candidateDirectories.length === 0)
	{
		throw new Error(`No security evidence artifact directory found under: ${absolutePath}`);
	}

	throw new Error(`Multiple security evidence artifact directories found under: ${absolutePath}`);
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

function extractSnykCounts(vulnerabilities)
{
	const counts = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0
	};

	for (const vulnerability of vulnerabilities)
	{
		const severity = vulnerability?.severity;

		if (severity in counts)
		{
			counts[severity] += 1;
		}
	}

	return counts;
}

function extractSbomFacts(sbomJson)
{
	return {
		format: sbomJson?.bomFormat || null,
		specVersion: sbomJson?.specVersion || null,
		componentCount: Array.isArray(sbomJson?.components) ? sbomJson.components.length : 0,
		primaryComponentName: sbomJson?.metadata?.component?.name || null,
		primaryComponentVersion: sbomJson?.metadata?.component?.version || null
	};
}

function parseSummaryContextRows(summaryHtml)
{
	const context = new Map();
	const rowPattern = /<tr><th scope="row">([^<]+)<\/th><td>([\s\S]*?)<\/td><\/tr>/g;

	for (const match of summaryHtml.matchAll(rowPattern))
	{
		context.set(match[1], stripHtml(match[2]));
	}

	return {
		version: asNullableString(context.get('Version')),
		repository: asNullableString(context.get('Repository')),
		workflowName: asNullableString(context.get('Workflow')),
		runId: asNullableString(context.get('Run ID')),
		runUrl: asNullableString(context.get('Run URL')),
		gitRef: asNullableString(context.get('Git ref')),
		gitCommit: asNullableString(context.get('Git commit')),
		drawioRef: asNullableString(context.get('drawio ref')),
		drawioCommit: asNullableString(context.get('drawio commit')),
		generatedAt: asNullableString(context.get('Generated at')),
		nodeVersion: asNullableString(context.get('Node.js')),
		npmVersion: asNullableString(context.get('npm')),
		electronVersion: asNullableString(context.get('Electron')),
		summaryFile: asNullableString(context.get('Summary file'))
	};
}

function parseSummaryEvidencePaths(summaryHtml)
{
	const artifactPathPattern = /<a href="[^"]+">((?:release|scans|sbom|summary|optional)\/[^<]+)<\/a>/g;

	return uniqueSorted(
		[...summaryHtml.matchAll(artifactPathPattern)].map((match) => normalizeRelativePath(match[1]))
	);
}

function parseSummaryStatus(summaryHtml)
{
	const statusMatch = /hero-([a-z-]+)"/.exec(summaryHtml);
	return statusMatch ? statusMatch[1] : null;
}

function deriveSecuritySummaryStatusFromEvidence(auditCounts, snykSummary)
{
	if (auditCounts.critical > 0 || auditCounts.high > 0)
	{
		return securitySummaryStatuses.blocked;
	}

	if (snykSummary.reportStatus === snykReportStatuses.exportFailed)
	{
		return securitySummaryStatuses.blocked;
	}

	if (snykSummary.findingsTotal > 0)
	{
		return securitySummaryStatuses.reviewRequired;
	}

	return securitySummaryStatuses.ready;
}

function normalizeExternalRunMetadata(externalRun = {}, options = {})
{
	return {
		label: asNullableString(options.label) || asNullableString(externalRun.label),
		dryRun: typeof externalRun.dryRun === 'boolean' ? externalRun.dryRun : null,
		runUrl: asNullableString(externalRun.runUrl),
		runId: asNullableString(externalRun.runId),
		workflowName: asNullableString(externalRun.workflowName),
		gitRef: asNullableString(externalRun.gitRef),
		gitCommit: asNullableString(externalRun.gitCommit),
		drawioRef: asNullableString(externalRun.drawioRef),
		drawioCommit: asNullableString(externalRun.drawioCommit),
		branchName: asNullableString(externalRun.branchName),
		prUrl: asNullableString(externalRun.prUrl),
		triggeredAt: asNullableString(externalRun.triggeredAt),
		durationSeconds: Number.isFinite(externalRun.durationSeconds) ? externalRun.durationSeconds : null,
		stepOutcomes: externalRun.stepOutcomes && typeof externalRun.stepOutcomes === 'object' ? externalRun.stepOutcomes : {},
		artifactDownloadPath: asNullableString(externalRun.artifactDownloadPath),
		stepSummaryPath: asNullableString(externalRun.stepSummaryPath),
		logExcerptPath: asNullableString(externalRun.logExcerptPath),
		notes: asNullableString(externalRun.notes)
	};
}

function compareOptionalField(checks, summaryValue, externalValue, label)
{
	if (!summaryValue || !externalValue)
	{
		return;
	}

	checks.push({
		name: label,
		passed: summaryValue === externalValue,
		summaryValue,
		externalValue
	});
}

function buildTraceabilityReport({artifactName, artifactPaths, expectedArtifactName, expectedSummaryStatus, externalRun, summary})
{
	const checks = [];
	const issues = [];

	checks.push({
		name: 'Artifact name matches summary version',
		passed: !summary.context.version || artifactName === expectedArtifactName,
		summaryValue: summary.context.version,
		artifactValue: artifactName
	});

	checks.push({
		name: 'Summary status matches raw evidence',
		passed: summary.status === expectedSummaryStatus,
		summaryValue: summary.status,
		expectedValue: expectedSummaryStatus
	});

	checks.push({
		name: 'Summary evidence links resolve to packaged files',
		passed: summary.evidencePaths.length > 0 && summary.evidencePaths.every((artifactPath) => artifactPaths.includes(artifactPath)),
		summaryValue: summary.evidencePaths,
		expectedValue: artifactPaths
	});

	if (summary.context.runId && summary.context.runUrl)
	{
		checks.push({
			name: 'Run URL contains summary run ID',
			passed: summary.context.runUrl.includes(summary.context.runId),
			summaryValue: summary.context.runUrl,
			expectedValue: summary.context.runId
		});
	}

	compareOptionalField(checks, summary.context.runUrl, externalRun.runUrl, 'Summary run URL matches external metadata');
	compareOptionalField(checks, summary.context.runId, externalRun.runId, 'Summary run ID matches external metadata');
	compareOptionalField(checks, summary.context.workflowName, externalRun.workflowName, 'Workflow name matches external metadata');
	compareOptionalField(checks, summary.context.gitRef, externalRun.gitRef, 'Git ref matches external metadata');
	compareOptionalField(checks, summary.context.gitCommit, externalRun.gitCommit, 'Git commit matches external metadata');
	compareOptionalField(checks, summary.context.drawioRef, externalRun.drawioRef, 'drawio ref matches external metadata');
	compareOptionalField(checks, summary.context.drawioCommit, externalRun.drawioCommit, 'drawio commit matches external metadata');

	if (externalRun.dryRun === false)
	{
		checks.push({
			name: 'Real run metadata contains release branch',
			passed: Boolean(externalRun.branchName),
			externalValue: externalRun.branchName
		});
		checks.push({
			name: 'Real run metadata contains pull request URL',
			passed: Boolean(externalRun.prUrl),
			externalValue: externalRun.prUrl
		});
	}

	for (const check of checks)
	{
		if (!check.passed)
		{
			issues.push(check.name);
		}
	}

	return {
		passed: issues.length === 0,
		checks,
		issues
	};
}

function buildCompletenessReport(artifactPaths)
{
	const requiredPaths = requiredArtifactFiles.map((file) => normalizeRelativePath(file.destination));
	const presentRequiredPaths = requiredPaths.filter((filePath) => artifactPaths.includes(filePath));
	const snykCandidates = requiredAlternativeArtifactFiles[0].candidates.map((candidate) => normalizeRelativePath(candidate.destination));
	const presentSnykEvidence = snykCandidates.filter((filePath) => artifactPaths.includes(filePath));

	return {
		requiredPaths,
		presentRequiredPaths,
		missingRequiredPaths: requiredPaths.filter((filePath) => !artifactPaths.includes(filePath)),
		snykEvidencePaths: presentSnykEvidence,
		exactlyOneSnykEvidence: presentSnykEvidence.length === 1,
		requiredPathsPresent: presentRequiredPaths.length === requiredPaths.length
	};
}

function buildInvariantSnapshot({artifactName, artifactPaths, auditCounts, snykSummary, sbom, summary})
{
	return {
		artifactName,
		artifactPaths,
		summaryStatus: summary.status,
		summaryFallback: summary.fallback,
		auditCounts,
		snykReportStatus: snykSummary.reportStatus,
		snykFindingsTotal: snykSummary.findingsTotal,
		snykCounts: snykSummary.counts,
		sbomFormat: sbom.format,
		sbomSpecVersion: sbom.specVersion,
		sbomComponentCount: sbom.componentCount,
		sbomPrimaryComponentName: sbom.primaryComponentName,
		sbomPrimaryComponentVersion: sbom.primaryComponentVersion,
		evidencePaths: summary.evidencePaths
	};
}

export async function analyzeSecurityEvidenceRun(options = {})
{
	if (!options.artifactDir)
	{
		throw new Error('Missing required option: artifactDir');
	}

	const artifactDir = await resolveArtifactDirectory(options.artifactDir);
	const artifactName = path.basename(artifactDir);
	const inventory = await collectArtifactInventory(artifactDir);
	const artifactPaths = inventory.map((entry) => entry.path);
	const validation = await validatePackagedSecurityEvidence({artifactDir});
	const completeness = buildCompletenessReport(artifactPaths);

	const auditResultsPath = path.join(artifactDir, 'scans', 'npm', 'audit-results.json');
	const sbomPath = path.join(artifactDir, 'sbom', 'sbom.cdx.json');
	const summaryPath = path.join(artifactDir, 'summary', 'security-summary.html');
	const snykReportPath = path.join(artifactDir, 'scans', 'snyk', 'snyk-report.json');
	const snykExportErrorPath = path.join(artifactDir, 'scans', 'snyk', 'snyk-export-error.txt');
	const releaseNotesPath = path.join(artifactDir, 'release', 'release-notes.md');

	const auditResults = await parseJsonFile(auditResultsPath);
	const sbomJson = await parseJsonFile(sbomPath);
	const summaryHtml = await readFile(summaryPath, 'utf8');
	const releaseNotes = await readFile(releaseNotesPath, 'utf8');
	const externalRun = normalizeExternalRunMetadata(
		options.externalRun || (options.metadataFile ? await parseJsonFile(path.resolve(options.metadataFile)) : {}),
		options
	);

	const auditCounts = extractAuditCounts(auditResults);
	const sbom = extractSbomFacts(sbomJson);
	const summary = {
		fallback: summaryHtml.includes(securitySummaryFallbackMarker),
		status: parseSummaryStatus(summaryHtml),
		context: parseSummaryContextRows(summaryHtml),
		evidencePaths: parseSummaryEvidencePaths(summaryHtml)
	};
	let resolvedSnykSummary = null;

	if (await exists(snykReportPath))
	{
		const snykReport = await parseJsonFile(snykReportPath);
		const vulnerabilities = Array.isArray(snykReport?.vulnerabilities) ? snykReport.vulnerabilities : [];
		const counts = extractSnykCounts(vulnerabilities);
		resolvedSnykSummary = {
			evidencePath: 'scans/snyk/snyk-report.json',
			reportStatus: vulnerabilities.length > 0 ? snykReportStatuses.findingsDetected : snykReportStatuses.noFindings,
			findingsTotal: vulnerabilities.length,
			counts,
			errorDetails: null
		};
	}
	else
	{
		const snykExportError = await readFile(snykExportErrorPath, 'utf8');
		resolvedSnykSummary = {
			evidencePath: 'scans/snyk/snyk-export-error.txt',
			reportStatus: snykReportStatuses.exportFailed,
			findingsTotal: 0,
			counts: {
				critical: 0,
				high: 0,
				medium: 0,
				low: 0
			},
			errorDetails: snykExportError.trim()
		};
	}

	const expectedArtifactName = summary.context.version ? getSecurityEvidenceArtifactName(summary.context.version) : artifactName;
	const expectedSummaryStatus = deriveSecuritySummaryStatusFromEvidence(auditCounts, resolvedSnykSummary);
	const traceability = buildTraceabilityReport({
		artifactName,
		artifactPaths,
		expectedArtifactName,
		expectedSummaryStatus,
		externalRun,
		summary
	});

	return {
		schemaVersion: 1,
		analyzedAt: new Date().toISOString(),
		artifact: {
			name: artifactName,
			dir: artifactDir,
			fileCount: inventory.length,
			files: inventory
		},
		externalRun,
		completeness,
		formalValidation: {
			passed: validation.isValid,
			errors: validation.validationErrors
		},
		audit: auditCounts,
		snyk: resolvedSnykSummary,
		sbom,
		summary,
		releaseNotes: {
			heading: releaseNotes.split(/\r?\n/).find((line) => line.trim().length > 0) || null
		},
		traceability,
		invariants: buildInvariantSnapshot({
			artifactName,
			artifactPaths,
			auditCounts,
			snykSummary: resolvedSnykSummary,
			sbom,
			summary
		})
	};
}

function parseCliOptions(argv = process.argv.slice(2))
{
	const {values} = parseArgs({
		args: argv,
		options: {
			'artifact-dir': {type: 'string'},
			'metadata-file': {type: 'string'},
			'label': {type: 'string'},
			'output-file': {type: 'string'}
		},
		strict: true
	});

	return {
		artifactDir: values['artifact-dir'],
		metadataFile: values['metadata-file'],
		label: values.label,
		outputFile: values['output-file']
	};
}

export async function main(argv = process.argv.slice(2))
{
	const options = parseCliOptions(argv);
	const analysis = await analyzeSecurityEvidenceRun(options);
	const output = JSON.stringify(analysis, null, 2);

	if (options.outputFile)
	{
		await writeFile(path.resolve(options.outputFile), output, 'utf8');
		console.log(`Wrote run analysis: ${path.resolve(options.outputFile)}`);
		return;
	}

	console.log(output);
}

const entryPoint = process.argv[1] ? path.resolve(process.argv[1]) : '';

if (entryPoint === fileURLToPath(import.meta.url))
{
	main().catch((error) =>
	{
		console.error(error.message);
		process.exitCode = 1;
	});
}

export {
	buildCompletenessReport,
	buildTraceabilityReport,
	deriveSecuritySummaryStatusFromEvidence,
	parseSummaryContextRows,
	parseSummaryEvidencePaths,
	parseSummaryStatus,
	resolveArtifactDirectory
};
