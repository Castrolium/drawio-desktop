import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { packageSecurityEvidence } from '../../build/security-evidence.mjs';

const SCRIPT = fileURLToPath(new URL('../../build/security-evidence.mjs', import.meta.url));
const VERSION = '30.3.12';
const DEFAULT_CONTEXT = {
	repository: 'jgraph/drawio-desktop',
	workflow: 'Prepare Release',
	runId: '123456789',
	ref: 'refs/heads/dev',
	commit: '0123456789abcdef0123456789abcdef01234567'
};
const GITHUB_ENV = {
	GITHUB_REPOSITORY: DEFAULT_CONTEXT.repository,
	GITHUB_WORKFLOW: DEFAULT_CONTEXT.workflow,
	GITHUB_RUN_ID: DEFAULT_CONTEXT.runId,
	GITHUB_REF: DEFAULT_CONTEXT.ref,
	GITHUB_SHA: DEFAULT_CONTEXT.commit
};
const DEFAULT_FILES = {
	'release-notes.md': '# Release notes\n\nSecurity update.\n',
	'audit-results.json': {
		metadata: {
			vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 }
		}
	},
	'audit-report.txt': 'found 0 vulnerabilities\n',
	'outdated-report.txt': '',
	'scan-status.json': { npmAuditJson: 0, npmAuditText: 0, npmOutdated: 0, snyk: 0, sbom: 0 },
	'snyk-report.json': { ok: true, vulnerabilities: [] },
	'sbom.cdx.json': {
		bomFormat: 'CycloneDX',
		specVersion: '1.6',
		components: [{ type: 'application', name: 'draw.io', version: VERSION }]
	}
};

async function createFixture(t, changes = {})
{
	const root = await mkdtemp(join(tmpdir(), 'drawio-evidence-'));
	const sourceDir = join(root, 'source');
	const outputDir = join(root, 'output');
	const files = { ...DEFAULT_FILES, ...changes };
	await mkdir(sourceDir, { recursive: true });
	t.after(() => rm(root, { recursive: true, force: true }));

	for (const [name, value] of Object.entries(files))
	{
		if (value !== null)
		{
			await writeFile(join(sourceDir, name), typeof value === 'string' ? value : JSON.stringify(value));
		}
	}

	return { sourceDir, outputDir };
}

async function listFiles(root, current = '')
{
	const entries = await readdir(join(root, current), { withFileTypes: true });
	const result = [];

	for (const entry of entries)
	{
		const relativePath = join(current, entry.name);

		if (entry.isDirectory())
		{
			result.push(...await listFiles(root, relativePath));
		}
		else
		{
			result.push(relativePath.replaceAll('\\', '/'));
		}
	}

	return result.sort();
}

async function packageFixture(fixture)
{
	return packageSecurityEvidence({ version: VERSION, context: DEFAULT_CONTEXT, ...fixture });
}

describe('security evidence packaging', () =>
{
	test('creates the exact ready evidence pack', async (t) =>
	{
		const result = await packageFixture(await createFixture(t));
		assert.equal(result.status, 'ready');
		assert.deepEqual(await listFiles(result.outputDir), [
			'release/release-notes.md',
			'sbom/sbom.cdx.json',
			'scans/npm/audit-report.txt',
			'scans/npm/audit-results.json',
			'scans/npm/outdated-report.txt',
			'scans/snyk/snyk-report.json',
			'summary/security-summary.html'
		]);

		const html = await readFile(join(result.outputDir, 'summary/security-summary.html'), 'utf8');
		assert.match(html, /Status:<\/strong> ready/);
		assert.match(html, /href="\.\.\/release\/release-notes\.md"/);
		assert.match(html, /href="\.\.\/sbom\/sbom\.cdx\.json"/);
		assert.match(html, /<tr><th>Specification<\/th><td>1\.6<\/td><\/tr>/);
		assert.match(html, /<tr><th>Components<\/th><td>1<\/td><\/tr>/);
		assert.doesNotMatch(html, /<(?:script|link)\b/i);
		const links = [...html.matchAll(/href="([^"]+)"/g)].map((match) => match[1]);
		assert.equal(links.length, 6);
		assert.ok(links.every((link) => link.startsWith('../')));
	});

	test('summarizes Snyk findings by severity and requires review', async (t) =>
	{
		const fixture = await createFixture(t, {
			'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], snyk: 1 },
			'snyk-report.json': {
				ok: false,
				vulnerabilities: [
					{ severity: 'low' },
					{ severity: 'low' },
					{ severity: 'medium' },
					{ severity: 'high' },
					{ severity: 'critical' }
				]
			}
		});
		const result = await packageFixture(fixture);
		assert.equal(result.status, 'review-required');

		const html = await readFile(join(result.outputDir, 'summary/security-summary.html'), 'utf8');
		const snykSection = html.split('<h2>Snyk findings</h2>')[1].split('<h2>Risk assessment</h2>')[0];
		assert.match(snykSection, /<tr><th>low<\/th><td>2<\/td><\/tr>/);
		assert.match(snykSection, /<tr><th>medium<\/th><td>1<\/td><\/tr>/);
		assert.match(snykSection, /<tr><th>high<\/th><td>1<\/td><\/tr>/);
		assert.match(snykSection, /<tr><th>critical<\/th><td>1<\/td><\/tr>/);
		assert.match(snykSection, /<tr><th>total<\/th><td>5<\/td><\/tr>/);
		assert.match(html, /Review is required before release/);
		assert.match(html, /href="\.\.\/scans\/snyk\/snyk-report\.json"/);
	});

	test('records and escapes a consistent GitHub run context', async (t) =>
	{
		const context = {
			...DEFAULT_CONTEXT,
			workflow: 'Prepare <Release> & verify',
			ref: 'refs/heads/<review>'
		};
		const result = await packageSecurityEvidence({
			version: VERSION,
			context,
			...await createFixture(t)
		});
		assert.equal(result.status, 'ready');

		const html = await readFile(join(result.outputDir, 'summary/security-summary.html'), 'utf8');
		assert.match(html, /jgraph\/drawio-desktop/);
		assert.match(html, /Prepare &lt;Release&gt; &amp; verify/);
		assert.match(html, /refs\/heads\/&lt;review&gt;/);
		assert.match(html, /0123456789abcdef0123456789abcdef01234567/);
		assert.match(html, /<tr><th>Run ID<\/th><td>123456789<\/td><\/tr>/);
		assert.doesNotMatch(html, /<Release>|<review>/);
		assert.match(html, /No blocking conditions were found/);
	});

	test('blocks incomplete GitHub run context', async (t) =>
	{
		const cases = [
			['empty repository', { repository: '' }],
			['invalid repository path', { repository: 'owner/repository/extra' }],
			['repository whitespace', { repository: ' jgraph/drawio-desktop ' }],
			['invalid repository character', { repository: 'jgraph/drawio\\desktop' }],
			['workflow', { workflow: '' }],
			['runId', { runId: '12x' }],
			['ref', { ref: '' }],
			['commit', { commit: 'abc' }]
		];

		for (const [name, change] of cases)
		{
			await t.test(name, async (t) =>
			{
				const result = await packageSecurityEvidence({
					version: VERSION,
					context: { ...DEFAULT_CONTEXT, ...change },
					...await createFixture(t)
				});
				assert.equal(result.status, 'blocked');
			});
		}
	});

	test('blocks high and critical npm audit findings', async (t) =>
	{
		for (const severity of ['high', 'critical'])
		{
			await t.test(severity, async (t) =>
			{
				const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 1 };
				counts[severity] = 1;
				const result = await packageFixture(await createFixture(t, {
					'audit-results.json': { metadata: { vulnerabilities: counts } },
					'scan-status.json': {
						...DEFAULT_FILES['scan-status.json'], npmAuditJson: 1, npmAuditText: 1
					}
				}));
				assert.equal(result.status, 'blocked');
				assert.match(result.errors.join('\n'), /high or critical/);
			});
		}
	});

	test('allows low and moderate npm audit findings', async (t) =>
	{
		const result = await packageFixture(await createFixture(t, {
			'audit-results.json': {
				metadata: {
					vulnerabilities: { info: 0, low: 1, moderate: 1, high: 0, critical: 0, total: 2 }
				}
			},
			'scan-status.json': {
				...DEFAULT_FILES['scan-status.json'], npmAuditJson: 1, npmAuditText: 1
			}
		}));
		assert.equal(result.status, 'ready');
	});

	test('rejects incomplete audit data, bad totals and exit mismatches', async (t) =>
	{
		const validCounts = DEFAULT_FILES['audit-results.json'].metadata.vulnerabilities;
		const cases = [
			{
				name: 'empty object',
				changes: { 'audit-results.json': {} },
				error: /vulnerability counts/
			},
			{
				name: 'missing severity',
				changes: {
					'audit-results.json': {
						metadata: { vulnerabilities: { ...validCounts, low: undefined } }
					}
				},
				error: /low count must be a non-negative integer/
			},
			{
				name: 'negative severity',
				changes: {
					'audit-results.json': {
						metadata: { vulnerabilities: { ...validCounts, moderate: -1 } }
					}
				},
				error: /moderate count must be a non-negative integer/
			},
			{
				name: 'non-integer severity',
				changes: {
					'audit-results.json': {
						metadata: { vulnerabilities: { ...validCounts, high: 0.5 } }
					}
				},
				error: /high count must be a non-negative integer/
			},
			{
				name: 'bad total',
				changes: {
					'audit-results.json': {
						metadata: {
							vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 1 }
						}
					}
				},
				error: /total does not match/
			},
			{
				name: 'exit mismatch',
				changes: {
					'audit-results.json': {
						metadata: {
							vulnerabilities: { info: 0, low: 1, moderate: 0, high: 0, critical: 0, total: 1 }
						}
					}
				},
				error: /exit code must be 1/
			}
		];

		for (const item of cases)
		{
			await t.test(item.name, async (t) =>
			{
				const result = await packageFixture(await createFixture(t, item.changes));
				assert.equal(result.status, 'blocked');
				assert.match(result.errors.join('\n'), item.error);
			});
		}
	});

	test('blocks incomplete status and technical scan exits', async (t) =>
	{
		const cases = [
			['missing status', { 'scan-status.json': null }, /Missing scan-status\.json/],
			['empty status', { 'scan-status.json': {} }, /npmAuditJson must be a non-negative integer/],
			['outdated error', {
				'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], npmOutdated: 2 }
			}, /npm outdated ended with a technical error/],
			['SBOM error', {
				'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], sbom: 1 }
			}, /SBOM generation ended with a technical error/]
		];

		for (const [name, changes, error] of cases)
		{
			await t.test(name, async (t) =>
			{
				const result = await packageFixture(await createFixture(t, changes));
				assert.equal(result.status, 'blocked');
				assert.match(result.errors.join('\n'), error);
			});
		}
	});

	test('rejects invalid CycloneDX data', async (t) =>
	{
		const cases = [
			{},
			{ bomFormat: 'CycloneDX', specVersion: 'not-a-version', components: [] },
			{ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{}] },
			{ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ type: 'other', name: 'x' }] }
		];

		for (const [index, sbom] of cases.entries())
		{
			await t.test(`invalid SBOM ${index + 1}`, async (t) =>
			{
				const result = await packageFixture(await createFixture(t, { 'sbom.cdx.json': sbom }));
				assert.equal(result.status, 'blocked');
				assert.match(result.errors.join('\n'), /valid CycloneDX BOM/);
			});
		}
	});

	test('reports a missing SBOM once', async (t) =>
	{
		const result = await packageFixture(await createFixture(t, { 'sbom.cdx.json': null }));
		assert.equal(result.status, 'blocked');
		assert.deepEqual(result.errors.filter((error) => error.includes('sbom.cdx.json')), ['Missing sbom.cdx.json']);
	});

	test('rejects invalid Snyk data and result mismatches', async (t) =>
	{
		const cases = [
			{
				name: 'empty object',
				files: { 'snyk-report.json': {} },
				error: /valid Snyk result/
			},
			{
				name: 'ok mismatch',
				files: {
					'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], snyk: 1 },
					'snyk-report.json': { ok: true, vulnerabilities: [{ severity: 'low' }] }
				},
				error: /inconsistent/
			},
			{
				name: 'exit mismatch',
				files: {
					'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], snyk: 0 },
					'snyk-report.json': { ok: false, vulnerabilities: [{ severity: 'low' }] }
				},
				error: /inconsistent/
			}
		];

		for (const item of cases)
		{
			await t.test(item.name, async (t) =>
			{
				const result = await packageFixture(await createFixture(t, item.files));
				assert.equal(result.status, 'blocked');
				assert.match(result.errors.join('\n'), item.error);
			});
		}
	});

	test('stages a partial pack when a required file is missing', async (t) =>
	{
		const result = await packageFixture(await createFixture(t, { 'release-notes.md': null }));
		assert.equal(result.status, 'blocked');
		assert.match(result.errors.join('\n'), /Missing release-notes\.md/);
		assert.doesNotMatch((await listFiles(result.outputDir)).join('\n'), /release-notes\.md/);
		assert.match((await listFiles(result.outputDir)).join('\n'), /security-summary\.html/);
	});

	test('requires non-empty textual evidence', async (t) =>
	{
		const cases = [
			['release notes', { 'release-notes.md': ' \n' }, /release-notes\.md must not be empty/],
			['audit report', { 'audit-report.txt': '\t' }, /audit-report\.txt must not be empty/],
			['outdated report', { 'outdated-report.txt': null }, /Missing outdated-report\.txt/],
			['Snyk diagnostic', {
				'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], snyk: 2 },
				'snyk-report.json': null,
				'snyk-export-error.txt': ' '
			}, /snyk-export-error\.txt must not be empty/]
		];

		for (const [name, changes, error] of cases)
		{
			await t.test(name, async (t) =>
			{
				const result = await packageFixture(await createFixture(t, changes));
				assert.equal(result.status, 'blocked');
				assert.match(result.errors.join('\n'), error);
			});
		}
	});

	test('rejects simultaneous Snyk report and diagnostic files', async (t) =>
	{
		const reportSelected = await packageFixture(await createFixture(t, {
			'snyk-export-error.txt': 'Snyk could not authenticate.\n'
		}));
		assert.equal(reportSelected.status, 'blocked');
		assert.match(reportSelected.errors.join('\n'), /Exactly one Snyk report or diagnostic/);
		const reportPaths = await listFiles(reportSelected.outputDir);
		assert.ok(reportPaths.includes('scans/snyk/snyk-report.json'));
		assert.ok(!reportPaths.includes('scans/snyk/snyk-export-error.txt'));

		const technicalFailure = await packageFixture(await createFixture(t, {
			'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], snyk: 2 },
			'snyk-export-error.txt': 'Snyk could not authenticate.\n'
		}));
		assert.equal(technicalFailure.status, 'blocked');
		const technicalPaths = await listFiles(technicalFailure.outputDir);
		assert.ok(!technicalPaths.includes('scans/snyk/snyk-report.json'));
		assert.ok(technicalPaths.includes('scans/snyk/snyk-export-error.txt'));
	});

	test('stages a Snyk diagnostic and blocks technical failures', async (t) =>
	{
		const result = await packageFixture(await createFixture(t, {
			'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], snyk: 2 },
			'snyk-report.json': null,
			'snyk-export-error.txt': 'Snyk did not produce a report.\n'
		}));
		assert.equal(result.status, 'blocked');
		assert.match(result.errors.join('\n'), /technical error/);
		const paths = await listFiles(result.outputDir);
		assert.ok(paths.includes('scans/snyk/snyk-export-error.txt'));
		assert.ok(!paths.includes('scans/snyk/snyk-report.json'));
	});

	test('does not turn unexpected I/O failures into missing files', async (t) =>
	{
		const fixture = await createFixture(t, { 'audit-report.txt': null });
		await mkdir(join(fixture.sourceDir, 'audit-report.txt'));
		await assert.rejects(packageFixture(fixture));
	});

	test('validates version and directory arguments before reading files', async () =>
	{
		await assert.rejects(packageSecurityEvidence({
			version: 'v30.3.12', sourceDir: 'source', outputDir: 'output', context: DEFAULT_CONTEXT
		}), /Version must use X\.Y\.Z format/);
		await assert.rejects(packageSecurityEvidence({
			version: VERSION, sourceDir: '', outputDir: 'output', context: DEFAULT_CONTEXT
		}), /Source and output directories are required/);
		await assert.rejects(packageSecurityEvidence({
			version: VERSION, sourceDir: 'source', outputDir: '', context: DEFAULT_CONTEXT
		}), /Source and output directories are required/);
	});

	test('returns success for review-required and failure for blocked evidence on the CLI', async (t) =>
	{
		const review = await createFixture(t, {
			'scan-status.json': { ...DEFAULT_FILES['scan-status.json'], snyk: 1 },
			'snyk-report.json': { ok: false, vulnerabilities: [{ severity: 'low' }] }
		});
		const reviewRun = spawnSync(process.execPath, [SCRIPT, '--version', VERSION,
			'--source-dir', review.sourceDir, '--output-dir', review.outputDir],
		{ env: { ...process.env, ...GITHUB_ENV } });
		assert.equal(reviewRun.status, 0, reviewRun.stderr.toString());

		const blocked = await createFixture(t, { 'sbom.cdx.json': {} });
		const blockedRun = spawnSync(process.execPath, [SCRIPT, '--version', VERSION,
			'--source-dir', blocked.sourceDir, '--output-dir', blocked.outputDir],
		{ env: { ...process.env, ...GITHUB_ENV } });
		assert.equal(blockedRun.status, 1);
	});
});
