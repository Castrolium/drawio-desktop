import {cp, mkdir, readFile, rm, stat} from 'node:fs/promises';
import path from 'node:path';
import {parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';

export const requiredArtifactFiles =
[
	{source: 'release-notes.md', destination: 'release/release-notes.md'},
	{source: 'audit-results.json', destination: 'scans/npm/audit-results.json'},
	{source: 'audit-report.txt', destination: 'scans/npm/audit-report.txt'},
	{source: 'outdated-report.txt', destination: 'scans/npm/outdated-report.txt'}
];

export const futureArtifactPaths =
[
	'summary/security-summary.html',
	'scans/snyk/snyk-report.json',
	'sbom/sbom.cdx.json',
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

async function validateAuditResultsJson(filePath)
{
	try
	{
		const auditJson = await readFile(filePath, 'utf8');
		JSON.parse(auditJson);
	}
	catch (e)
	{
		throw new Error('Invalid JSON in required evidence file: audit-results.json');
	}
}

export async function packageSecurityEvidence(options = {})
{
	const version = options.version;
	const workspaceDir = path.resolve(options.workspaceDir || process.cwd());
	const outputDir = path.resolve(options.outputDir || process.cwd());
	const artifactName = getSecurityEvidenceArtifactName(version);
	const artifactDir = path.join(outputDir, artifactName);
	const packagedFiles = [];
	
	await rm(artifactDir, {recursive: true, force: true});
	
	for (const file of requiredArtifactFiles)
	{
		const sourcePath = path.join(workspaceDir, file.source);
		const destinationPath = path.join(artifactDir, file.destination);
		
		await assertRequiredFileExists(sourcePath, file.source);
		
		if (file.source === 'audit-results.json')
		{
			await validateAuditResultsJson(sourcePath);
		}
		
		await mkdir(path.dirname(destinationPath), {recursive: true});
		await cp(sourcePath, destinationPath, {force: true});
		packagedFiles.push(normalizeRelativePath(file.destination));
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
