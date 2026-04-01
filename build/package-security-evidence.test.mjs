import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
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

test('packages the current security evidence files into the expected structure', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': JSON.stringify({
			metadata: {
				vulnerabilities: {
					critical: 0,
					high: 0,
					moderate: 1,
					low: 2
				}
			}
		}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': createValidSbom()
	});
	
	const result = await packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
	const artifactDir = path.join(outputDir, getSecurityEvidenceArtifactName('1.2.3'));
	const releaseNotesPath = path.join(artifactDir, 'release', 'release-notes.md');
	const auditJsonPath = path.join(artifactDir, 'scans', 'npm', 'audit-results.json');
	const sbomPath = path.join(artifactDir, 'sbom', 'sbom.cdx.json');
	
	assert.equal(result.artifactName, 'security-evidence-pack-v1.2.3');
	assert.deepEqual(result.packagedFiles, [
		'release/release-notes.md',
		'scans/npm/audit-results.json',
		'scans/npm/audit-report.txt',
		'scans/npm/outdated-report.txt',
		'sbom/sbom.cdx.json'
	]);
	assert.deepEqual(result.futureArtifactPaths, futureArtifactPaths);
	assert.equal(await readFile(releaseNotesPath, 'utf8'), '# Release Notes\n');
	assert.equal(await readFile(auditJsonPath, 'utf8'), await readFile(path.join(workspaceDir, 'audit-results.json'), 'utf8'));
	assert.equal(await readFile(sbomPath, 'utf8'), await readFile(path.join(workspaceDir, 'sbom.cdx.json'), 'utf8'));
});

test('uses the workspace package.json version when version option is omitted', async (t) =>
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

test('fails when a required evidence file is missing', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'audit-results.json': JSON.stringify({metadata: {vulnerabilities: {critical: 0, high: 0}}}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': createValidSbom()
	});
	
	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Missing required evidence file: release-notes\.md/);
});

test('fails when sbom.cdx.json is missing', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': JSON.stringify({metadata: {vulnerabilities: {critical: 0, high: 0}}}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n'
	});

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Missing required evidence file: sbom\.cdx\.json/);
});

test('fails when audit-results.json is not valid JSON', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': '{invalid json',
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': createValidSbom()
	});
	
	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid JSON in required evidence file: audit-results\.json/);
});

test('fails when sbom.cdx.json is not valid JSON', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': JSON.stringify({metadata: {vulnerabilities: {critical: 0, high: 0}}}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': '{invalid json'
	});

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid JSON in required evidence file: sbom\.cdx\.json/);
});

test('fails when sbom.cdx.json is not a CycloneDX SBOM', async (t) =>
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, {
		'release-notes.md': '# Release Notes\n',
		'audit-results.json': JSON.stringify({metadata: {vulnerabilities: {critical: 0, high: 0}}}),
		'audit-report.txt': 'audit report\n',
		'outdated-report.txt': 'outdated report\n',
		'sbom.cdx.json': JSON.stringify({
			bomFormat: 'SPDX',
			specVersion: '2.3'
		})
	});

	await assert.rejects(() => packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	}), /Invalid SBOM format in required evidence file: sbom\.cdx\.json/);
});
