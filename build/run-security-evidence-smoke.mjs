import assert from 'node:assert/strict';
import {mkdtemp, readdir, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import {createSecurityEvidenceFixtureFiles, getDefaultSecurityEvidenceMetadata, writeWorkspaceFiles} from './security-evidence-fixture.mjs';
import {generateSecuritySummary} from './generate-security-summary.mjs';
import {packageSecurityEvidence} from './package-security-evidence.mjs';
import {runSecurityEvidencePreflight} from './security-evidence-preflight.mjs';

const fixedGeneratedAt = '2026-04-01T10:00:00Z';

async function createSmokeWorkspace(rootDir)
{
	const workspaceDir = path.join(rootDir, 'workspace');
	const outputDir = path.join(rootDir, 'output');

	await writeWorkspaceFiles(workspaceDir, createSecurityEvidenceFixtureFiles());
	await generateSecuritySummary({
		workspaceDir,
		...getDefaultSecurityEvidenceMetadata({
			generatedAt: fixedGeneratedAt
		})
	});

	return {workspaceDir, outputDir};
}

async function snapshotDirectory(rootDir, prefix = '')
{
	const entries = await readdir(rootDir, {withFileTypes: true});
	const files = [];

	for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name)))
	{
		const relativePath = prefix ? path.posix.join(prefix, entry.name) : entry.name;
		const absolutePath = path.join(rootDir, entry.name);

		if (entry.isDirectory())
		{
			files.push(...await snapshotDirectory(absolutePath, relativePath));
			continue;
		}

		files.push({
			path: relativePath,
			contents: await readFile(absolutePath, 'utf8')
		});
	}

	return files;
}

async function runSmokeIteration()
{
	const rootDir = await mkdtemp(path.join(tmpdir(), 'drawio-security-evidence-smoke-'));

	try
	{
		const {workspaceDir, outputDir} = await createSmokeWorkspace(rootDir);
		const result = await packageSecurityEvidence({
			workspaceDir,
			outputDir,
			version: '1.2.3'
		});

		return {
			artifactName: result.artifactName,
			packagedFiles: result.packagedFiles,
			files: await snapshotDirectory(result.artifactDir)
		};
	}
	finally
	{
		await rm(rootDir, {recursive: true, force: true});
	}
}

export async function main()
{
	runSecurityEvidencePreflight({
		commandLabel: 'test:security-evidence:smoke',
		requireNodeMajor: 24,
		requireNpmContext: true
	});

	const firstRun = await runSmokeIteration();
	const secondRun = await runSmokeIteration();

	assert.equal(firstRun.artifactName, secondRun.artifactName);
	assert.deepEqual(firstRun.packagedFiles, secondRun.packagedFiles);
	assert.deepEqual(firstRun.files, secondRun.files);

	console.log(`Smoke run passed for ${firstRun.artifactName}`);
	console.log(`Packaged files: ${firstRun.packagedFiles.length}`);
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
