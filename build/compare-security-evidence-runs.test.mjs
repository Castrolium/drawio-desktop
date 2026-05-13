import assert from 'node:assert/strict';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {analyzeSecurityEvidenceRun} from './analyze-security-evidence-run.mjs';
import {
	compareSecurityEvidenceRuns,
	renderSecurityEvidenceComparisonMarkdown
} from './compare-security-evidence-runs.mjs';
import {generateSecuritySummary} from './generate-security-summary.mjs';
import {packageSecurityEvidence} from './package-security-evidence.mjs';
import {
	createSecurityEvidenceFixtureFiles,
	getDefaultSecurityEvidenceMetadata,
	writeWorkspaceFiles
} from './security-evidence-fixture.mjs';

async function createTempDirs(t)
{
	const rootDir = await mkdtemp(path.join(tmpdir(), 'drawio-security-evidence-compare-'));
	const workspaceDir = path.join(rootDir, 'workspace');
	const outputDir = path.join(rootDir, 'output');

	await mkdir(workspaceDir, {recursive: true});
	await mkdir(outputDir, {recursive: true});
	t.after(() => rm(rootDir, {recursive: true, force: true}));

	return {workspaceDir, outputDir};
}

async function createBaseAnalysis(t)
{
	const {workspaceDir, outputDir} = await createTempDirs(t);
	await writeWorkspaceFiles(workspaceDir, createSecurityEvidenceFixtureFiles());
	await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata()
	});

	const packagedArtifact = await packageSecurityEvidence({
		version: '1.2.3',
		workspaceDir,
		outputDir
	});

	return analyzeSecurityEvidenceRun({
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
}

function cloneAnalysis(analysis)
{
	return JSON.parse(JSON.stringify(analysis));
}

test('compares repeated dry-runs and a real run into a campaign report', async (t) =>
{
	const baseAnalysis = await createBaseAnalysis(t);
	const dryRunB = cloneAnalysis(baseAnalysis);
	const dryRunC = cloneAnalysis(baseAnalysis);
	const realRunD = cloneAnalysis(baseAnalysis);

	dryRunB.externalRun.label = 'Dry-Run B';
	dryRunB.externalRun.runId = '21489875202';
	dryRunB.externalRun.runUrl = 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875202';
	dryRunB.summary.context.runId = '21489875202';
	dryRunB.summary.context.runUrl = 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875202';
	dryRunB.summary.context.generatedAt = '2026-04-01T10:10:00Z';
	dryRunB.traceability.passed = true;
	dryRunB.traceability.issues = [];

	dryRunC.externalRun.label = 'Dry-Run C';
	dryRunC.externalRun.runId = '21489875203';
	dryRunC.externalRun.runUrl = 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875203';
	dryRunC.summary.context.runId = '21489875203';
	dryRunC.summary.context.runUrl = 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875203';
	dryRunC.summary.context.generatedAt = '2026-04-01T10:20:00Z';
	dryRunC.traceability.passed = true;
	dryRunC.traceability.issues = [];

	realRunD.externalRun.label = 'Real-Run D';
	realRunD.externalRun.dryRun = false;
	realRunD.externalRun.runId = '21489875204';
	realRunD.externalRun.runUrl = 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875204';
	realRunD.externalRun.branchName = 'releases/v1.2.3';
	realRunD.externalRun.prUrl = 'https://github.com/Castrolium/drawio-desktop/pull/99';
	realRunD.summary.context.runId = '21489875204';
	realRunD.summary.context.runUrl = 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875204';
	realRunD.summary.context.generatedAt = '2026-04-01T10:30:00Z';
	realRunD.traceability.passed = true;
	realRunD.traceability.issues = [];

	const report = compareSecurityEvidenceRuns([
		baseAnalysis,
		dryRunB,
		dryRunC,
		realRunD
	], {
		title: 'Validation Campaign'
	});
	const markdown = renderSecurityEvidenceComparisonMarkdown(report);

	assert.equal(report.reproducibility.rating, 'Erfuellt');
	assert.equal(report.productPath.rating, 'Erfuellt');
	assert.equal(report.criteria.length, 5);
	assert.match(markdown, /Run-Matrix/);
	assert.match(markdown, /Produktivpfad/);
	assert.match(markdown, /Dry-Run A/);
	assert.match(markdown, /Real-Run D/);
});
