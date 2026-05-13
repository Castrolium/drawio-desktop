import process from 'node:process';
import {parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

import {assertValidSecurityEvidenceVersion} from './security-evidence-contract.mjs';

function parseRequiredNodeMajor(value)
{
	if (value === undefined)
	{
		return null;
	}

	const parsedValue = Number.parseInt(value, 10);

	if (!Number.isInteger(parsedValue) || parsedValue <= 0)
	{
		throw new Error(`Invalid required Node.js major version: ${value}`);
	}

	return parsedValue;
}

function getInstalledNodeMajor()
{
	const versionMatch = /^v(\d+)\./.exec(process.version);
	return versionMatch ? Number.parseInt(versionMatch[1], 10) : null;
}

function getCommandLabel(commandLabel)
{
	return commandLabel || 'this command';
}

export function runSecurityEvidencePreflight(options = {})
{
	if (options.version !== undefined)
	{
		assertValidSecurityEvidenceVersion(options.version);
	}

	const requiredNodeMajor = options.requireNodeMajor === null || options.requireNodeMajor === undefined
		? null
		: parseRequiredNodeMajor(String(options.requireNodeMajor));
	const installedNodeMajor = getInstalledNodeMajor();

	if (requiredNodeMajor !== null && installedNodeMajor !== requiredNodeMajor)
	{
		throw new Error(`Unsupported Node.js version for ${getCommandLabel(options.commandLabel)}: expected ${requiredNodeMajor}.x, found ${process.version}.`);
	}

	if (options.requireNpmContext && !process.env.npm_execpath)
	{
		throw new Error(`Missing npm context for ${getCommandLabel(options.commandLabel)}. Install Node.js with npm and run it via "npm run ${options.commandLabel}".`);
	}

	return {
		nodeVersion: process.version,
		npmExecPath: process.env.npm_execpath || null
	};
}

function parseCliOptions(argv = process.argv.slice(2))
{
	const {values} = parseArgs({
		args: argv,
		options: {
			version: {type: 'string'},
			command: {type: 'string'},
			'require-node-major': {type: 'string'},
			'require-npm-context': {type: 'boolean', default: false}
		},
		strict: true
	});

	return {
		version: values.version,
		commandLabel: values.command,
		requireNodeMajor: values['require-node-major'],
		requireNpmContext: values['require-npm-context']
	};
}

export async function main(argv = process.argv.slice(2))
{
	const result = runSecurityEvidencePreflight(parseCliOptions(argv));
	console.log(`Security evidence preflight passed with Node.js ${result.nodeVersion}`);
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
