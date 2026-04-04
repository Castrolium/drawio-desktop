import process from 'node:process';
import {spawn} from 'node:child_process';

const generatorVersion = '4.2.1';
const npmCliPath = process.env.npm_execpath;
const outputFile = 'sbom.cdx.json';
const sbomArgs = [
	'exec',
	'--yes',
	`--package=@cyclonedx/cyclonedx-npm@${generatorVersion}`,
	'--',
	'cyclonedx-npm',
	'--package-lock-only',
	'--output-reproducible',
	'--validate',
	'--output-format',
	'JSON',
	'--output-file',
	outputFile
];

function assertNpmExecPath()
{
	if (!npmCliPath)
	{
		throw new Error('Missing npm context for SBOM generation. Install Node.js with npm and run "npm run generate-sbom".');
	}
}

async function run()
{
	assertNpmExecPath();

	const exitCode = await new Promise((resolve, reject) =>
	{
		const child = spawn(process.execPath, [npmCliPath, ...sbomArgs], {
			stdio: 'inherit',
			env: {
				...process.env,
				// Keep the MVP scope fixed to the complete npm project.
				NODE_ENV: ''
			}
		});
		
		child.on('error', reject);
		child.on('close', resolve);
	});
	
	if (exitCode !== 0)
	{
		process.exitCode = exitCode ?? 1;
	}
}

run().catch((e) =>
{
	console.error(e.message);
	process.exitCode = 1;
});
