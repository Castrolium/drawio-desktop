import assert from 'node:assert/strict';
import process from 'node:process';
import test from 'node:test';

import {runSecurityEvidencePreflight} from './security-evidence-preflight.mjs';

function getInstalledNodeMajor()
{
	return Number.parseInt(process.version.replace(/^v/, '').split('.')[0], 10);
}

test('passes preflight when the version format is valid', () =>
{
	const originalNpmExecPath = process.env.npm_execpath;
	process.env.npm_execpath = 'npm-cli.js';

	try
	{
		const result = runSecurityEvidencePreflight({
			commandLabel: 'test:security-evidence:smoke',
			requireNodeMajor: getInstalledNodeMajor(),
			requireNpmContext: true,
			version: '1.2.3'
		});

		assert.equal(result.nodeVersion, process.version);
	}
	finally
	{
		process.env.npm_execpath = originalNpmExecPath;
	}
});

test('fails preflight when the version format is invalid', () =>
{
	assert.throws(() => runSecurityEvidencePreflight({
		version: '1.2'
	}), /Invalid security evidence version/);
});

test('fails preflight when the Node.js major version does not match', () =>
{
	assert.throws(() => runSecurityEvidencePreflight({
		commandLabel: 'test:security-evidence:smoke',
		requireNodeMajor: getInstalledNodeMajor() + 1
	}), /Unsupported Node\.js version/);
});

test('fails preflight when npm context is required but unavailable', () =>
{
	const originalNpmExecPath = process.env.npm_execpath;
	delete process.env.npm_execpath;

	try
	{
		assert.throws(() => runSecurityEvidencePreflight({
			commandLabel: 'test:security-evidence:smoke',
			requireNpmContext: true
		}), /Missing npm context/);
	}
	finally
	{
		process.env.npm_execpath = originalNpmExecPath;
	}
});
