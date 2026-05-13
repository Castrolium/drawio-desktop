import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
	assembleSecurityEvidence,
	futureArtifactPaths,
	getSecurityEvidenceArtifactName,
	packageSecurityEvidence,
	validatePackagedSecurityEvidence
} from './package-security-evidence.mjs';
import {
	createAuditResults,
	createSecurityEvidenceFixtureFiles,
	createSnykReport,
	createValidSummaryHtml,
	writeWorkspaceFiles
} from './security-evidence-fixture.mjs';

async function createTempDirs(t)
{
	const rootDir = await mkdtemp(path.join(tmpdir(), 'drawio-security-evidence-'));
	const workspaceDir = path.join(rootDir, 'workspace');
	const outputDir = path.join(rootDir, 'output');

	await mkdir(workspaceDir, {recursive: true});
	await mkdir(outputDir, {recursive: true});
	t.after(() => rm(rootDir, {recursive: true, force: true}));

	return {workspaceDir, outputDir};
}

function createRequiredEvidenceFiles(overrides = {})
{
	return {
		...createSecurityEvidenceFixtureFiles({
			'summary/security-summary.html': createValidSummaryHtml()
		}),
		...overrides
	};
}

test('packages the current security evidence files into the expected structure', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'snyk-report.json': createSnykReport([
			{severity: 'high'},
			{severity: 'medium'}
		])
	}));

	const result = await packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const artifactDir = path.join(outputDir, getSecurityEvidenceArtifactName('1.2.3'));
	const summaryPath = path.join(artifactDir, 'summary', 'security-summary.html');
	const releaseNotesPath = path.join(artifactDir, 'release', 'release-notes.md');
	const auditJsonPath = path.join(artifactDir, 'scans', 'npm', 'audit-results.json');
	const sbomPath = path.join(artifactDir, 'sbom', 'sbom.cdx.json');

	assert.equal(result.artifactName, 'security-evidence-pack-v1.2.3');
	assert.equal(result.validationPassed, true);
	assert.deepEqual(result.packagedFiles, [
		'summary/security-summary.html',
		'release/release-notes.md',
		'scans/npm/audit-results.json',
		'scans/npm/audit-report.txt',
		'scans/npm/outdated-report.txt',
		'sbom/sbom.cdx.json',
		'scans/snyk/snyk-report.json'
	]);
	assert.deepEqual(result.futureArtifactPaths, futureArtifactPaths);
	assert.equal(await readFile(summaryPath, 'utf8'), createValidSummaryHtml());
	assert.equal(await readFile(releaseNotesPath, 'utf8'), '# Release Notes for 1.2.3\n\nSecurity fixes.\n');
	assert.equal(await readFile(auditJsonPath, 'utf8'), await readFile(path.join(workspaceDir, 'audit-results.json'), 'utf8'));
	assert.equal(await readFile(sbomPath, 'utf8'), await readFile(path.join(workspaceDir, 'sbom.cdx.json'), 'utf8'));
});

test('uses the workspace package.json version when version option is omitted', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'package.json': JSON.stringify({version: '4.5.6'})
	}));

	const result = await packageSecurityEvidence({
		workspaceDir,
		outputDir
	});

	assert.equal(result.artifactName, 'security-evidence-pack-v4.5.6');
});

test('stages a fallback summary when the generated summary is unavailable', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['summary/security-summary.html'];
	await writeWorkspaceFiles(workspaceDir, files);

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir,
		generatedAt: '2026-04-01T10:00:00Z'
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});
	const fallbackSummary = await readFile(path.join(assembledResult.artifactDir, 'summary', 'security-summary.html'), 'utf8');

	assert.match(fallbackSummary, /Fallback Security Summary/);
	assert.match(fallbackSummary, /data-security-evidence-summary="fallback"/);
	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Fallback security summary cannot satisfy release validation: summary/security-summary.html'
	]);

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Fallback security summary cannot satisfy release validation: summary\/security-summary\.html/);
});

test('reports missing required evidence after staging the artifact', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['release-notes.md'];
	await writeWorkspaceFiles(workspaceDir, files);

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});

	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Missing required evidence file: release/release-notes.md'
	]);
});

test('reports invalid JSON after staging the artifact', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'audit-results.json': '{invalid json'
	}));

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});

	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Invalid JSON in required evidence file: scans/npm/audit-results.json'
	]);
});

test('reports invalid SBOM content after staging the artifact', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'sbom.cdx.json': JSON.stringify({
			bomFormat: 'SPDX',
			specVersion: '2.3'
		})
	}));

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});

	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Invalid SBOM format in required evidence file: sbom/sbom.cdx.json'
	]);
});

test('packages Snyk export diagnostics when the report is unavailable', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['snyk-report.json'];
	files['snyk-export-error.txt'] = 'Snyk export failed\n';
	await writeWorkspaceFiles(workspaceDir, files);

	const result = await packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});

	assert.deepEqual(result.packagedFiles, [
		'summary/security-summary.html',
		'release/release-notes.md',
		'scans/npm/audit-results.json',
		'scans/npm/audit-report.txt',
		'scans/npm/outdated-report.txt',
		'sbom/sbom.cdx.json',
		'scans/snyk/snyk-export-error.txt'
	]);
});

test('reports missing Snyk evidence after staging the artifact', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['snyk-report.json'];
	await writeWorkspaceFiles(workspaceDir, files);

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});

	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Missing required Snyk evidence file: expected one of scans/snyk/snyk-report.json, scans/snyk/snyk-export-error.txt'
	]);
});

test('reports invalid Snyk JSON after staging the artifact', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'snyk-report.json': '{invalid json'
	}));

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});

	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Invalid JSON in required evidence file: scans/snyk/snyk-report.json'
	]);
});

test('reports conflicting Snyk evidence files after staging the artifact', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'snyk-report.json': createSnykReport([{severity: 'high'}]),
		'snyk-export-error.txt': 'Snyk export failed\n'
	}));

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});

	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Conflicting Snyk evidence files: expected only one of scans/snyk/snyk-report.json, scans/snyk/snyk-export-error.txt'
	]);
});

test('reports invalid generated summary HTML after staging the artifact', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'summary/security-summary.html': 'not html'
	}));

	const assembledResult = await assembleSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});

	assert.equal(validationResult.isValid, false);
	assert.deepEqual(validationResult.validationErrors, [
		'Invalid HTML in required evidence file: summary/security-summary.html'
	]);
});
