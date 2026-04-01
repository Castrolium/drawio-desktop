import {cp, mkdir, readFile, rm, stat} from 'node:fs/promises';
import path from 'node:path';
import {parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';

export const requiredArtifactFiles =
[
	{source: 'release-notes.md', destination: 'release/release-notes.md'},
	{source: 'audit-results.json', destination: 'scans/npm/audit-results.json'},
	{source: 'audit-report.txt', destination: 'scans/npm/audit-report.txt'},
	{source: 'outdated-report.txt', destination: 'scans/npm/outdated-report.txt'},
	{source: 'sbom.cdx.json', destination: 'sbom/sbom.cdx.json'}
];

export const requiredAlternativeArtifactFiles =
[
	{
		description: 'Snyk evidence',
		candidates: [
			{source: 'snyk-report.json', destination: 'scans/snyk/snyk-report.json'},
			{source: 'snyk-export-error.txt', destination: 'scans/snyk/snyk-export-error.txt'}
		]
	}
];

export const futureArtifactPaths =
[
	'summary/security-summary.html',
	'optional/security-summary.pdf',
	'optional/metadata.json',
	'optional/checksums.sha256'
];

export function getSecurityEvidenceArtifactName(version)
{
	if (!version || typeof version !== 'string')
	{
		throw new Error('Missing required option: version');
	}
	
	return `security-evidence-pack-v${version}`;
}

function normalizeRelativePath(filePath)
{
	return filePath.split(path.sep).join('/');
}

async function assertRequiredFileExists(filePath, sourceName)
{
	let fileStat = null;
	
	try
	{
		fileStat = await stat(filePath);
	}
	catch (e)
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
	try
	{
		const fileContents = await readFile(filePath, 'utf8');
		return JSON.parse(fileContents);
	}
	catch (e)
	{
		throw new Error(`Invalid JSON in required evidence file: ${sourceName}`);
	}
}

async function validateAuditResultsJson(filePath)
{
	await parseRequiredJsonFile(filePath, 'audit-results.json');
}

async function validateSbomFile(filePath)
{
	const sbomJson = await parseRequiredJsonFile(filePath, 'sbom.cdx.json');

	if (sbomJson?.bomFormat !== 'CycloneDX')
	{
		throw new Error('Invalid SBOM format in required evidence file: sbom.cdx.json');
	}
}

async function validateSnykReportJson(filePath)
{
	await parseRequiredJsonFile(filePath, 'snyk-report.json');
}

const requiredFileValidators = new Map([
	['audit-results.json', validateAuditResultsJson],
	['sbom.cdx.json', validateSbomFile],
	['snyk-report.json', validateSnykReportJson]
]);

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

async function copyArtifactFile(sourcePath, destinationPath, sourceName)
{
	await assertRequiredFileExists(sourcePath, sourceName);

	const validator = requiredFileValidators.get(sourceName);

	if (validator)
	{
		await validator(sourcePath);
	}

	await mkdir(path.dirname(destinationPath), {recursive: true});
	await cp(sourcePath, destinationPath, {force: true});
}

async function packageAlternativeArtifactFileGroup(workspaceDir, artifactDir, fileGroup, packagedFiles)
{
	const availableFiles = [];

	for (const candidate of fileGroup.candidates)
	{
		const sourcePath = path.join(workspaceDir, candidate.source);
		const fileStat = await tryStat(sourcePath);

		if (fileStat?.isFile())
		{
			availableFiles.push(candidate);
		}
	}

	if (availableFiles.length === 0)
	{
		throw new Error(`Missing required ${fileGroup.description} file: expected one of ${fileGroup.candidates.map((candidate) => candidate.source).join(', ')}`);
	}

	if (availableFiles.length > 1)
	{
		throw new Error(`Conflicting ${fileGroup.description} files: expected only one of ${fileGroup.candidates.map((candidate) => candidate.source).join(', ')}`);
	}

	const selectedFile = availableFiles[0];
	const sourcePath = path.join(workspaceDir, selectedFile.source);
	const destinationPath = path.join(artifactDir, selectedFile.destination);

	await copyArtifactFile(sourcePath, destinationPath, selectedFile.source);
	packagedFiles.push(normalizeRelativePath(selectedFile.destination));
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

export async function packageSecurityEvidence(options = {})
{
	const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
	const outputDir = path.resolve(options.outputDir || process.cwd());
	const version = await resolveVersion(options.version, workspaceDir);
	const artifactName = getSecurityEvidenceArtifactName(version);
	const artifactDir = path.join(outputDir, artifactName);
	const packagedFiles = [];
	
	await rm(artifactDir, {recursive: true, force: true});
	
	for (const file of requiredArtifactFiles)
	{
		const sourcePath = path.join(workspaceDir, file.source);
		const destinationPath = path.join(artifactDir, file.destination);

		await copyArtifactFile(sourcePath, destinationPath, file.source);
		packagedFiles.push(normalizeRelativePath(file.destination));
	}

	for (const fileGroup of requiredAlternativeArtifactFiles)
	{
		await packageAlternativeArtifactFileGroup(workspaceDir, artifactDir, fileGroup, packagedFiles);
	}
	
	return {
		artifactName,
		artifactDir,
		packagedFiles,
		futureArtifactPaths: futureArtifactPaths.map(normalizeRelativePath)
	};
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
			}
		},
		strict: true
	});
	
	return {
		version: values.version,
		workspaceDir: values['workspace-dir'],
		outputDir: values['output-dir']
	};
}

export async function main(argv = process.argv.slice(2))
{
	const result = await packageSecurityEvidence(parseCliOptions(argv));
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

const entryPoint = process.argv[1] ? path.resolve(process.argv[1]) : '';

if (entryPoint === fileURLToPath(import.meta.url))
{
	main().catch((e) =>
	{
		console.error(e.message);
		process.exitCode = 1;
	});
}
