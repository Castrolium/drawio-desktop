import assert from 'node:assert/strict';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {analyzeSecurityEvidenceRun} from './analyze-security-evidence-run.mjs';
import {generateSecuritySummary} from './generate-security-summary.mjs';
import {packageSecurityEvidence} from './package-security-evidence.mjs';
import {
	createSecurityEvidenceFixtureFiles,
	getDefaultSecurityEvidenceMetadata,
	writeWorkspaceFiles
} from './security-evidence-fixture.mjs';

async function createTempDirs(t)
{
	const rootDir = await mkdtemp(path.join(tmpdir(), 'drawio-security-evidence-analysis-'));
	const workspaceDir = path.join(rootDir, 'workspace');
	const outputDir = path.join(rootDir, 'output');

	await mkdir(workspaceDir, {recursive: true});
	await mkdir(outputDir, {recursive: true});
	t.after(() => rm(rootDir, {recursive: true, force: true}));

	return {workspaceDir, outputDir};
}

async function createPackagedArtifact(t, metadataOverrides = {}, fileOverrides = {})
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createSecurityEvidenceFixtureFiles(fileOverrides));
	await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata(metadataOverrides)
	});

	return packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});
}

test('analyzes a valid packaged artifact and derives invariant comparison data', async (t) =>
{
	const packagedArtifact = await createPackagedArtifact(t);
	const analysis = await analyzeSecurityEvidenceRun({
		artifactDir: packagedArtifact.artifactDir,
		externalRun: {
			label: 'Dry-Run A',
			dryRun: true,
			runId: '21489875201',
			runUrl: 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875201',
			workflowName: 'Prepare Release',
			gitRef: 'refs/heads/dev',
			gitCommit: 'abc123def456',
			drawioRef: 'v1.2.3',
			drawioCommit: 'drawio987654'
		}
	});

	assert.equal(analysis.formalValidation.passed, true);
	assert.equal(analysis.completeness.requiredPathsPresent, true);
	assert.equal(analysis.completeness.exactlyOneSnykEvidence, true);
	assert.equal(analysis.summary.fallback, false);
	assert.equal(analysis.summary.status, 'ready');
	assert.equal(analysis.traceability.passed, true);
	assert.equal(analysis.snyk.reportStatus, 'no-findings');
	assert.equal(analysis.invariants.sbomSpecVersion, '1.6');
	assert.match(analysis.releaseNotes.heading, /Release Notes/);
	assert.ok(analysis.summary.evidencePaths.includes('sbom/sbom.cdx.json'));
	assert.ok(analysis.summary.evidencePaths.includes('scans/snyk/snyk-report.json'));
});

test('reports traceability mismatches when external metadata contradicts the summary context', async (t) =>
{
	const packagedArtifact = await createPackagedArtifact(t);
	const analysis = await analyzeSecurityEvidenceRun({
		artifactDir: packagedArtifact.artifactDir,
		externalRun: {
			label: 'Dry-Run B',
			dryRun: true,
			runId: '21489875201',
			runUrl: 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875201',
			workflowName: 'Prepare Release',
			gitRef: 'refs/heads/dev',
			gitCommit: 'different-commit',
			drawioRef: 'v1.2.3',
			drawioCommit: 'drawio987654'
		}
	});

	assert.equal(analysis.traceability.passed, false);
	assert.ok(analysis.traceability.issues.includes('Git commit matches external metadata'));
});
