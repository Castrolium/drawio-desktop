import {mkdir, writeFile} from 'node:fs/promises';
import path from 'node:path';

export async function writeWorkspaceFiles(workspaceDir, files)
{
	for (const [relativePath, contents] of Object.entries(files))
	{
		const fullPath = path.join(workspaceDir, relativePath);
		await mkdir(path.dirname(fullPath), {recursive: true});
		await writeFile(fullPath, contents, 'utf8');
	}
}

export function createAuditResults(overrides = {})
{
	return JSON.stringify({
		metadata: {
			vulnerabilities: {
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0,
				...overrides
			}
		}
	});
}

export function createSnykReport(vulnerabilities = [])
{
	return JSON.stringify({
		ok: vulnerabilities.length === 0,
		vulnerabilities
	});
}

export function createValidSbom()
{
	return JSON.stringify({
		bomFormat: 'CycloneDX',
		specVersion: '1.6',
		version: 1,
		metadata: {
			component: {
				type: 'application',
				name: 'draw.io',
				version: '1.2.3'
			}
		},
		components: [
			{name: 'electron', version: '39.6.1'},
			{name: 'buffer', version: '6.0.3'}
		]
	});
}

export function createValidSummaryHtml()
{
	return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Security Summary</title>
  </head>
  <body>
    <h1>Security Summary</h1>
  </body>
</html>
`;
}

export function createSecurityEvidenceFixtureFiles(overrides = {})
{
	return {
		'release-notes.md': '# Release Notes for 1.2.3\n\nSecurity fixes.\n',
		'audit-results.json': createAuditResults(),
		'audit-report.txt': 'found 0 vulnerabilities\n',
		'outdated-report.txt': 'Package Current Wanted Latest\n',
		'sbom.cdx.json': createValidSbom(),
		'snyk-report.json': createSnykReport(),
		'package.json': JSON.stringify({
			version: '1.2.3',
			repository: {
				type: 'git',
				url: 'git@github.com:jgraph/drawio-desktop.git'
			}
		}),
		'package-lock.json': JSON.stringify({
			packages: {
				'node_modules/electron': {
					version: '39.6.1'
				}
			}
		}),
		...overrides
	};
}

export function getDefaultSecurityEvidenceMetadata(overrides = {})
{
	return {
		version: '1.2.3',
		repository: 'https://github.com/jgraph/drawio-desktop',
		workflowName: 'Prepare Release',
		runId: '21489875201',
		runUrl: 'https://github.com/jgraph/drawio-desktop/actions/runs/21489875201',
		gitRef: 'refs/heads/dev',
		gitCommit: 'abc123def456',
		drawioRef: 'v1.2.3',
		drawioCommit: 'drawio987654',
		nodeVersion: 'v24.0.0',
		npmVersion: '11.0.0',
		electronVersion: '39.6.1',
		generatedAt: '2026-04-01T10:00:00Z',
		...overrides
	};
}
