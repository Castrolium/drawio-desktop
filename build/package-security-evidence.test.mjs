import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
	requiredAlternativeArtifactFiles,
	futureArtifactPaths,
	getSecurityEvidenceArtifactName,
	packageSecurityEvidence
} from './package-security-evidence.mjs';

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
				moderate: 1,
				low: 2,
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
		components: []
	});
}

function createValidSummaryHtml()
{
	return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Security Summary</title>
  </head>
  <body>
    <h1>Security Summary</h1>
  </body>
</html>
`;
}

function createRequiredEvidenceFiles(overrides = {})
{
	return {
		'summary/security-summary.html': createValidSummaryHtml(),
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': createAuditResults(),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': createValidSbom(),
		'snyk-report.json': createSnykReport(),
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
	assert.equal(await readFile(releaseNotesPath, 'utf8'), '# Release Notes\n');
	assert.equal(await readFile(auditJsonPath, 'utf8'), await readFile(path.join(workspaceDir, 'audit-results.json'), 'utf8'));
	assert.equal(await readFile(sbomPath, 'utf8'), await readFile(path.join(workspaceDir, 'sbom.cdx.json'), 'utf8'));
});

test('uses the workspace package.json version when version option is omitted', async (t) =>
<<<<<<< ours
=======
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'package.json': JSON.stringify({version: '4.5.6'}),
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': JSON.stringify({metadata: {vulnerabilities: {critical: 0, high: 0}}}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': createValidSbom()
	});

	const result = await packageSecurityEvidence({
		workspaceDir,
		outputDir
	});

	assert.equal(result.artifactName, 'security-evidence-pack-v4.5.6');
});

test('fails when version option is omitted and workspace package.json is missing', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': JSON.stringify({metadata: {vulnerabilities: {critical: 0, high: 0}}}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': createValidSbom()
	});

	await assert.rejects(() => packageSecurityEvidence({
		workspaceDir,
		outputDir
	}), /Missing required option: version \(provide --version or a valid workspace package\.json\)/);
});

test('fails when version option is omitted and workspace package.json has no version', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'package.json': JSON.stringify({name: 'drawio'}),
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': JSON.stringify({metadata: {vulnerabilities: {critical: 0, high: 0}}}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': createValidSbom()
	});

	await assert.rejects(() => packageSecurityEvidence({
		workspaceDir,
		outputDir
	}), /Missing required option: version \(workspace package\.json has no string version\)/);
});

test('fails when a required evidence file is missing', async (t) =>
>>>>>>> theirs
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

test('fails when a required evidence file is missing', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['release-notes.md'];
	await writeWorkspaceFiles(workspaceDir, files);

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Missing required evidence file: release-notes\.md/);
});

test('fails when security-summary.html is missing', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['summary/security-summary.html'];
	await writeWorkspaceFiles(workspaceDir, files);

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Missing required evidence file: summary\/security-summary\.html/);
});

test('fails when security-summary.html is not valid HTML', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'summary/security-summary.html': 'not html'
	}));

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid HTML in required evidence file: summary\/security-summary\.html/);
});

test('fails when sbom.cdx.json is missing', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['sbom.cdx.json'];
	await writeWorkspaceFiles(workspaceDir, files);

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Missing required evidence file: sbom\.cdx\.json/);
});

test('fails when audit-results.json is not valid JSON', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'audit-results.json': '{invalid json'
	}));

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid JSON in required evidence file: audit-results\.json/);
});

test('fails when sbom.cdx.json is not valid JSON', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'sbom.cdx.json': '{invalid json'
	}));

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid JSON in required evidence file: sbom\.cdx\.json/);
});

test('fails when sbom.cdx.json is not a CycloneDX SBOM', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'sbom.cdx.json': JSON.stringify({
			bomFormat: 'SPDX',
			specVersion: '2.3'
		})
	}));

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid SBOM format in required evidence file: sbom\.cdx\.json/);
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

test('fails when no Snyk evidence file is available', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	const files = createRequiredEvidenceFiles();
	delete files['snyk-report.json'];
	await writeWorkspaceFiles(workspaceDir, files);

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), new RegExp(`Missing required ${requiredAlternativeArtifactFiles[0].description} file: expected one of snyk-report\\.json, snyk-export-error\\.txt`));
});

test('fails when snyk-report.json is not valid JSON', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'snyk-report.json': '{invalid json'
	}));

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid JSON in required evidence file: snyk-report\.json/);
});

test('fails when both Snyk report and export error files are present', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createRequiredEvidenceFiles({
		'snyk-report.json': createSnykReport([{severity: 'high'}]),
		'snyk-export-error.txt': 'Snyk export failed\n'
	}));

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Conflicting Snyk evidence files: expected only one of snyk-report\.json, snyk-export-error\.txt/);
});
