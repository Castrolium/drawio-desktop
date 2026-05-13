import {cp, mkdir, readFile, rm, stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';

import {
	futureArtifactPaths,
	getOrderedArtifactPaths,
	getRequiredArtifactFilesWithoutSummary,
	getSecurityEvidenceArtifactName,
	normalizeRelativePath,
	requiredAlternativeArtifactFiles,
	requiredArtifactFiles,
	securitySummaryRelativePath,
	securitySummaryFallbackMarker
} from './security-evidence-contract.mjs';
import {renderFallbackSecuritySummaryHtml} from './generate-security-summary.mjs';

export {
	futureArtifactPaths,
	getSecurityEvidenceArtifactName,
	requiredAlternativeArtifactFiles,
	requiredArtifactFiles
} from './security-evidence-contract.mjs';

function formatValidationErrors(errors)
{
	return `Security evidence validation failed:\n - ${errors.join('\n - ')}`;
}

function normalizePackagedFiles(packagedFileSet)
{
	return getOrderedArtifactPaths().filter((filePath) => packagedFileSet.has(filePath));
}

async function tryStat(filePath)
{
	try
	{
		return await stat(filePath);
	}
	catch (e)
	{
		return null;
	}
}

async function assertArtifactFileExists(filePath, sourceName)
{
	const fileStat = await tryStat(filePath);

	if (!fileStat)
	{
		throw new Error(`Missing required evidence file: ${sourceName}`);
	}

	if (!fileStat.isFile())
	{
		throw new Error(`Required evidence path is not a file: ${sourceName}`);
	}
}

async function parseRequiredJsonFile(filePath, sourceName)
{
	await assertArtifactFileExists(filePath, sourceName);

	try
	{
		return JSON.parse(await readFile(filePath, 'utf8'));
	}
	catch (e)
	{
		throw new Error(`Invalid JSON in required evidence file: ${sourceName}`);
	}
}

async function validateAuditResultsJson(filePath)
{
	await parseRequiredJsonFile(filePath, 'scans/npm/audit-results.json');
}

async function validateSbomFile(filePath)
{
	const sbomJson = await parseRequiredJsonFile(filePath, 'sbom/sbom.cdx.json');

	if (sbomJson?.bomFormat !== 'CycloneDX')
	{
		throw new Error('Invalid SBOM format in required evidence file: sbom/sbom.cdx.json');
	}
}

async function validateSnykReportJson(filePath)
{
	await parseRequiredJsonFile(filePath, 'scans/snyk/snyk-report.json');
}

async function validateSecuritySummaryHtml(filePath)
{
	await assertArtifactFileExists(filePath, securitySummaryRelativePath);
	const fileContents = await readFile(filePath, 'utf8');

	if (!fileContents.match(/<!DOCTYPE html>/i) || !fileContents.match(/<html[\s>]/i))
	{
		throw new Error(`Invalid HTML in required evidence file: ${securitySummaryRelativePath}`);
	}

	if (fileContents.includes(securitySummaryFallbackMarker))
	{
		throw new Error(`Fallback security summary cannot satisfy release validation: ${securitySummaryRelativePath}`);
	}
}

const requiredFileValidators = new Map([
	['scans/npm/audit-results.json', validateAuditResultsJson],
	['sbom/sbom.cdx.json', validateSbomFile],
	['scans/snyk/snyk-report.json', validateSnykReportJson],
	[securitySummaryRelativePath, validateSecuritySummaryHtml]
]);

function getEvidenceLabelForArtifactPath(filePath)
{
	const evidenceLabels = new Map([
		['release/release-notes.md', 'Release notes'],
		['scans/npm/audit-results.json', 'npm audit results (JSON)'],
		['scans/npm/audit-report.txt', 'npm audit report (text)'],
		['scans/npm/outdated-report.txt', 'npm outdated report'],
		['sbom/sbom.cdx.json', 'CycloneDX SBOM'],
		['scans/snyk/snyk-report.json', 'Snyk report (JSON)'],
		['scans/snyk/snyk-export-error.txt', 'Snyk export diagnostics']
	]);

	return evidenceLabels.get(filePath) || filePath;
}

function buildFallbackEvidenceInventory(packagedFiles)
{
	const summaryDirectory = path.posix.dirname(securitySummaryRelativePath);

	return packagedFiles
		.filter((filePath) => filePath !== securitySummaryRelativePath)
		.map((filePath) => ({
			label: getEvidenceLabelForArtifactPath(filePath),
			artifactPath: filePath,
			href: path.posix.relative(summaryDirectory, filePath)
		}));
}

function buildAssemblyFindings(packagedFileSet)
{
	const findings = [];

	for (const file of getRequiredArtifactFilesWithoutSummary())
	{
		if (!packagedFileSet.has(file.destination))
		{
			findings.push(`Required evidence was not available during packaging: ${file.destination}`);
		}
	}

	for (const fileGroup of requiredAlternativeArtifactFiles)
	{
		const availableCandidates = fileGroup.candidates.filter((candidate) => packagedFileSet.has(candidate.destination));

		if (availableCandidates.length === 0)
		{
			findings.push(`No ${fileGroup.description} file was available during packaging.`);
			continue;
		}

		if (availableCandidates.length > 1)
		{
			findings.push(`Multiple ${fileGroup.description} files were staged; strict validation will fail until only one remains.`);
		}
	}

	return findings;
}

async function tryCopyArtifactFile(sourcePath, destinationPath)
{
	const sourceStat = await tryStat(sourcePath);

	if (!sourceStat?.isFile())
	{
		return false;
	}

	await mkdir(path.dirname(destinationPath), {recursive: true});
	await cp(sourcePath, destinationPath, {force: true});
	return true;
}

async function copyRequiredArtifactFiles(workspaceDir, artifactDir, packagedFileSet)
{
	for (const file of getRequiredArtifactFilesWithoutSummary())
	{
		const sourcePath = path.join(workspaceDir, file.source);
		const destinationPath = path.join(artifactDir, file.destination);

		if (await tryCopyArtifactFile(sourcePath, destinationPath))
		{
			packagedFileSet.add(normalizeRelativePath(file.destination));
		}
	}
}

async function copyAlternativeArtifactFileGroups(workspaceDir, artifactDir, packagedFileSet)
{
	for (const fileGroup of requiredAlternativeArtifactFiles)
	{
		for (const candidate of fileGroup.candidates)
		{
			const sourcePath = path.join(workspaceDir, candidate.source);
			const destinationPath = path.join(artifactDir, candidate.destination);

			if (await tryCopyArtifactFile(sourcePath, destinationPath))
			{
				packagedFileSet.add(normalizeRelativePath(candidate.destination));
			}
		}
	}
}

async function stageFallbackSecuritySummary(artifactDir, packagedFileSet, options)
{
	const packagedFiles = normalizePackagedFiles(packagedFileSet);
	const outputPath = path.join(artifactDir, securitySummaryRelativePath);
	const html = renderFallbackSecuritySummaryHtml({
		artifactName: options.artifactName,
		evidenceInventory: buildFallbackEvidenceInventory(packagedFiles),
		generatedAt: options.generatedAt || new Date().toISOString(),
		reasons: buildAssemblyFindings(packagedFileSet),
		version: options.version
	});

	await mkdir(path.dirname(outputPath), {recursive: true});
	await writeFile(outputPath, html, 'utf8');
	packagedFileSet.add(securitySummaryRelativePath);
}

async function copyGeneratedSecuritySummary(workspaceDir, artifactDir)
{
	const sourcePath = path.join(workspaceDir, securitySummaryRelativePath);
	const destinationPath = path.join(artifactDir, securitySummaryRelativePath);
	return tryCopyArtifactFile(sourcePath, destinationPath);
}

async function resolveVersion(providedVersion, workspaceDir)
{
	if (providedVersion && typeof providedVersion === 'string')
	{
		return providedVersion;
	}

	const packageJsonPath = path.join(workspaceDir, 'package.json');
	const packageJson = await parseRequiredJsonFile(packageJsonPath, 'package.json');

	if (!packageJson?.version || typeof packageJson.version !== 'string')
	{
		throw new Error('Missing required option: version');
	}

	return packageJson.version;
}

export async function assembleSecurityEvidence(options = {})
{
	const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
	const outputDir = path.resolve(options.outputDir || process.cwd());
	const version = await resolveVersion(options.version, workspaceDir);
	const artifactName = getSecurityEvidenceArtifactName(version);
	const artifactDir = path.join(outputDir, artifactName);
	const packagedFileSet = new Set();

	await rm(artifactDir, {recursive: true, force: true});
	await copyRequiredArtifactFiles(workspaceDir, artifactDir, packagedFileSet);
	await copyAlternativeArtifactFileGroups(workspaceDir, artifactDir, packagedFileSet);
	await stageFallbackSecuritySummary(artifactDir, packagedFileSet, {
		artifactName,
		generatedAt: options.generatedAt,
		version
	});

	if (await copyGeneratedSecuritySummary(workspaceDir, artifactDir))
	{
		packagedFileSet.add(securitySummaryRelativePath);
	}

	return {
		artifactDir,
		artifactName,
		futureArtifactPaths: futureArtifactPaths.map(normalizeRelativePath),
		outputDir,
		packagedFiles: normalizePackagedFiles(packagedFileSet),
		version,
		workspaceDir
	};
}

export async function validatePackagedSecurityEvidence(options = {})
{
	const artifactDir = path.resolve(options.artifactDir);
	const validationErrors = [];

	for (const file of requiredArtifactFiles)
	{
		const destinationPath = normalizeRelativePath(file.destination);
		const validator = requiredFileValidators.get(destinationPath);
		const absolutePath = path.join(artifactDir, destinationPath);

		try
		{
			await assertArtifactFileExists(absolutePath, destinationPath);

			if (validator)
			{
				await validator(absolutePath);
			}
		}
		catch (e)
		{
			validationErrors.push(e.message);
		}
	}

	for (const fileGroup of requiredAlternativeArtifactFiles)
	{
		const availableCandidates = [];

		for (const candidate of fileGroup.candidates)
		{
			const destinationPath = normalizeRelativePath(candidate.destination);
			const absolutePath = path.join(artifactDir, destinationPath);
			const fileStat = await tryStat(absolutePath);

			if (fileStat?.isFile())
			{
				availableCandidates.push(candidate);

				const validator = requiredFileValidators.get(destinationPath);

				if (validator)
				{
					try
					{
						await validator(absolutePath);
					}
					catch (e)
					{
						validationErrors.push(e.message);
					}
				}
			}
		}

		if (availableCandidates.length === 0)
		{
			validationErrors.push(`Missing required ${fileGroup.description} file: expected one of ${fileGroup.candidates.map((candidate) => normalizeRelativePath(candidate.destination)).join(', ')}`);
		}
		else if (availableCandidates.length > 1)
		{
			validationErrors.push(`Conflicting ${fileGroup.description} files: expected only one of ${fileGroup.candidates.map((candidate) => normalizeRelativePath(candidate.destination)).join(', ')}`);
		}
	}

	return {
		artifactDir,
		isValid: validationErrors.length === 0,
		validationErrors
	};
}

export async function packageSecurityEvidence(options = {})
{
	const assembledResult = await assembleSecurityEvidence(options);
	const validationResult = await validatePackagedSecurityEvidence({
		artifactDir: assembledResult.artifactDir
	});
	const result = {
		...assembledResult,
		validationErrors: validationResult.validationErrors,
		validationPassed: validationResult.isValid
	};

	if (!validationResult.isValid)
	{
		const error = new Error(formatValidationErrors(validationResult.validationErrors));
		error.name = 'SecurityEvidenceValidationError';
		error.result = result;
		throw error;
	}

	return result;
}

function parseCliOptions(argv = process.argv.slice(2))
{
	const {values} = parseArgs({
		args: argv,
		options: {
			version: {
				type: 'string'
			},
			'workspace-dir': {
				type: 'string'
			},
			'output-dir': {
				type: 'string'
			},
			'generated-at': {
				type: 'string'
			}
		},
		strict: true
	});

	return {
		generatedAt: values['generated-at'],
		outputDir: values['output-dir'],
		version: values.version,
		workspaceDir: values['workspace-dir']
	};
}

function logPackagedArtifact(result)
{
	console.log(`Packaged security evidence artifact: ${result.artifactName}`);

	for (const filePath of result.packagedFiles)
	{
		console.log(` - ${filePath}`);
	}

	console.log('Reserved future artifact paths:');

	for (const filePath of result.futureArtifactPaths)
	{
		console.log(` - ${filePath}`);
	}
}

export async function main(argv = process.argv.slice(2))
{
	try
	{
		const result = await packageSecurityEvidence(parseCliOptions(argv));
		logPackagedArtifact(result);
	}
	catch (e)
	{
		if (e?.result)
		{
			logPackagedArtifact(e.result);
		}

		console.error(e.message);
		process.exitCode = 1;
	}
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
