import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
	generateSecuritySummary,
	securitySummaryRelativePath
} from './generate-security-summary.mjs';

async function createTempWorkspace(t)
{
	const workspaceDir = await mkdtemp(path.join(tmpdir(), 'drawio-security-summary-'));
	t.after(() => rm(workspaceDir, {recursive: true, force: true}));
	return workspaceDir;
}

async function writeWorkspaceFiles(workspaceDir, files)
{
	for (const [relativePath, contents] of Object.entries(files))
	{
		const fullPath = path.join(workspaceDir, relativePath);
		await mkdir(path.dirname(fullPath), {recursive: true});
		await writeFile(fullPath, contents, 'utf8');
	}
}

function createAuditResults(overrides = {})
{
	return JSON.stringify({
		metadata: {
			vulnerabilities: {
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0,
				...overrides
			}
		}
	});
}

function createSnykReport(vulnerabilities = [])
{
	return JSON.stringify({
		ok: vulnerabilities.length === 0,
		vulnerabilities
	});
}

function createValidSbom()
{
	return JSON.stringify({
		bomFormat: 'CycloneDX',
		specVersion: '1.6',
		version: 1,
		metadata: {
			component: {
				type: 'application',
				name: 'draw.io',
				version: '1.2.3'
			}
		},
		components: [
			{name: 'electron', version: '39.6.1'},
			{name: 'buffer', version: '6.0.3'}
		]
	});
}

function createBaseEvidenceFiles(overrides = {})
{
	return {
		'release-notes.md': '# Release Notes for 1.2.3\n\nSecurity fixes.\n',
		'audit-results.json': createAuditResults(),
		'audit-report.txt': 'found 0 vulnerabilities\n',
		'outdated-report.txt': 'Package Current Wanted Latest\n',
		'sbom.cdx.json': createValidSbom(),
		'snyk-report.json': createSnykReport(),
		'package.json': JSON.stringify({
			version: '1.2.3',
			repository: {
				type: 'git',
				url: 'git@github.com:jgraph/drawio-desktop.git'
			}
		}),
		'package-lock.json': JSON.stringify({
			packages: {
				'node_modules/electron': {
					version: '39.6.1'
				}
			}
		}),
		...overrides
	};
}

function getDefaultMetadata()
{
	return {
		version: '1.2.3',
		repository: 'https://github.com/jgraph/drawio-desktop',
		workflowName: 'Prepare Release',
		runId: '21489875201',
		runUrl: 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875201',
		gitRef: 'refs/heads/dev',
		gitCommit: 'abc123def456',
		drawioRef: 'v1.2.3',
		drawioCommit: 'drawio987654',
		nodeVersion: 'v24.0.0',
		npmVersion: '11.0.0',
		electronVersion: '39.6.1',
		generatedAt: '2026-04-01T10:00:00Z'
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
		...getDefaultMetadata()
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
		...getDefaultMetadata()
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
		...getDefaultMetadata()
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
		...getDefaultMetadata()
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
		...getDefaultMetadata()
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
		...getDefaultMetadata()
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
		...getDefaultMetadata()
	}), /Conflicting Snyk evidence files: expected only one of snyk-report\.json, snyk-export-error\.txt/);
});

test('writes artifact-relative links from the summary folder to packaged evidence files', async (t) =>
{
	const workspaceDir = await createTempWorkspace(t);
	await writeWorkspaceFiles(workspaceDir, createBaseEvidenceFiles());

	await generateSecuritySummary({
		workspaceDir,
		...getDefaultMetadata()
	});

	const html = await readFile(path.join(workspaceDir, securitySummaryRelativePath), 'utf8');

	assert.match(html, /href="\.\.\/release\/release-notes\.md"/);
	assert.match(html, /href="\.\.\/scans\/npm\/audit-results\.json"/);
	assert.match(html, /href="\.\.\/scans\/npm\/audit-report\.txt"/);
	assert.match(html, /href="\.\.\/scans\/npm\/outdated-report\.txt"/);
	assert.match(html, /href="\.\.\/scans\/snyk\/snyk-report\.json"/);
	assert.match(html, /href="\.\.\/sbom\/sbom\.cdx\.json"/);
});
