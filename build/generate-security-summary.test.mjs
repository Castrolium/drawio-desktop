import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
	generateSecuritySummary,
	renderFallbackSecuritySummaryHtml
} from './generate-security-summary.mjs';
import {
	createAuditResults,
	createSecurityEvidenceFixtureFiles,
	createSnykReport,
	getDefaultSecurityEvidenceMetadata,
	writeWorkspaceFiles
} from './security-evidence-fixture.mjs';
import {securitySummaryRelativePath} from './security-evidence-contract.mjs';

async function createTempWorkspace(t)
{
	const workspaceDir = await mkdtemp(path.join(tmpdir(), 'drawio-security-summary-'));
	t.after(() => rm(workspaceDir, {recursive: true, force: true}));
	return workspaceDir;
}

function createBaseEvidenceFiles(overrides = {})
{
	return {
		...createSecurityEvidenceFixtureFiles(),
		...overrides
	};
}

test('generates a ready summary when audit and Snyk gates pass', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	await writeWorkspaceFiles(workspaceDir, createBaseEvidenceFiles({
		'audit-results.json': createAuditResults({moderate: 1, low: 2}),
		'snyk-report.json': createSnykReport()
	}));

	const result = await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	});
	const summaryPath = path.join(workspaceDir, securitySummaryRelativePath);
	const html = await readFile(summaryPath, 'utf8');

	assert.equal(result.status, 'ready');
	assert.equal(result.outputPath, summaryPath);
	assert.match(html, /Security Summary/);
	assert.match(html, /status-ready/);
	assert.match(html, /Release 1\.2\.3/);
	assert.match(html, /Prepare Release/);
	assert.match(html, /21489875201/);
	assert.match(html, /39\.6\.1/);
	assert.match(html, /\.\.\/release\/release-notes\.md/);
	assert.match(html, /\.\.\/scans\/npm\/audit-results\.json/);
	assert.match(html, /\.\.\/scans\/snyk\/snyk-report\.json/);
	assert.match(html, /\.\.\/sbom\/sbom\.cdx\.json/);
	assert.doesNotMatch(html, /data-security-evidence-summary="fallback"/);
});

test('generates a blocked summary when only Snyk export diagnostics are available', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	const files = createBaseEvidenceFiles();
	delete files['snyk-report.json'];
	files['snyk-export-error.txt'] = 'Snyk export failed\nReason: Missing token\n';
	await writeWorkspaceFiles(workspaceDir, files);

	const result = await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	});
	const html = await readFile(path.join(workspaceDir, securitySummaryRelativePath), 'utf8');

	assert.equal(result.status, 'blocked');
	assert.match(html, /export-failed/);
	assert.match(html, /\.\.\/scans\/snyk\/snyk-export-error\.txt/);
	assert.match(html, /Missing token/);
});

test('generates a blocked summary when npm audit reports critical or high findings', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	await writeWorkspaceFiles(workspaceDir, createBaseEvidenceFiles({
		'audit-results.json': createAuditResults({critical: 1, high: 2, moderate: 0, low: 0})
	}));

	const result = await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	});
	const html = await readFile(path.join(workspaceDir, securitySummaryRelativePath), 'utf8');

	assert.equal(result.status, 'blocked');
	assert.match(html, /1 critical and 2 high vulnerabilities/);
});

test('generates a review-required summary when Snyk findings are present', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	await writeWorkspaceFiles(workspaceDir, createBaseEvidenceFiles({
		'snyk-report.json': createSnykReport([
			{severity: 'high'},
			{severity: 'medium'}
		])
	}));

	const result = await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	});
	const html = await readFile(path.join(workspaceDir, securitySummaryRelativePath), 'utf8');

	assert.equal(result.status, 'review-required');
	assert.match(html, /status-review-required/);
	assert.match(html, /findings-detected/);
	assert.match(html, /2 findings/);
});

test('fails when a required evidence input is missing', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	const files = createBaseEvidenceFiles();
	delete files['audit-results.json'];
	await writeWorkspaceFiles(workspaceDir, files);

	await assert.rejects(() => generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	}), /Missing required evidence file: audit-results\.json/);
});

test('fails when a required JSON evidence file is invalid', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	await writeWorkspaceFiles(workspaceDir, createBaseEvidenceFiles({
		'audit-results.json': '{invalid json'
	}));

	await assert.rejects(() => generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	}), /Invalid JSON in required evidence file: audit-results\.json/);
});

test('fails when both Snyk evidence files are present', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	await writeWorkspaceFiles(workspaceDir, createBaseEvidenceFiles({
		'snyk-export-error.txt': 'Snyk export failed\n'
	}));

	await assert.rejects(() => generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	}), /Conflicting Snyk evidence files: expected only one of snyk-report\.json, snyk-export-error\.txt/);
});

test('writes artifact-relative links from the summary folder to packaged evidence files', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	await writeWorkspaceFiles(workspaceDir, createBaseEvidenceFiles());

	await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	});

	const html = await readFile(path.join(workspaceDir, securitySummaryRelativePath), 'utf8');

	assert.match(html, /href="\.\.\/release\/release-notes\.md"/);
	assert.match(html, /href="\.\.\/scans\/npm\/audit-results\.json"/);
	assert.match(html, /href="\.\.\/scans\/npm\/audit-report\.txt"/);
	assert.match(html, /href="\.\.\/scans\/npm\/outdated-report\.txt"/);
	assert.match(html, /href="\.\.\/scans\/snyk\/snyk-report\.json"/);
	assert.match(html, /href="\.\.\/sbom\/sbom\.cdx\.json"/);
});

test('renders a fallback summary with staged evidence links', async () =>
{
	const html = renderFallbackSecuritySummaryHtml({
		artifactName: 'security-evidence-pack-v1.2.3',
		evidenceInventory: [
			{
				label: 'Release notes',
				artifactPath: 'release/release-notes.md',
				href: '../release/release-notes.md'
			}
		],
		generatedAt: '2026-04-01T10:00:00Z',
		reasons: ['Generated summary was not available.'],
		version: '1.2.3'
	});

	assert.match(html, /Fallback Security Summary/);
	assert.match(html, /data-security-evidence-summary="fallback"/);
	assert.match(html, /\.\.\/release\/release-notes\.md/);
	assert.match(html, /Generated summary was not available/);
});
