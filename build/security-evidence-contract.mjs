import path from 'node:path';

export const securityEvidenceVersionPattern = /^[0-9]+\.[0-9]+\.[0-9]+$/;
export const securityEvidenceVersionFormat = 'X.Y.Z';
export const securityEvidenceArtifactPrefix = 'security-evidence-pack-v';
export const securitySummaryRelativePath = 'summary/security-summary.html';
export const securitySummaryFallbackMarker = 'data-security-evidence-summary="fallback"';

export const securitySummaryStatuses = Object.freeze({
	ready: 'ready',
	reviewRequired: 'review-required',
	blocked: 'blocked'
});

export const snykReportStatuses = Object.freeze({
	noFindings: 'no-findings',
	findingsDetected: 'findings-detected',
	exportFailed: 'export-failed'
});

export const requiredArtifactFiles = Object.freeze([
	{source: securitySummaryRelativePath, destination: securitySummaryRelativePath},
	{source: 'release-notes.md', destination: 'release/release-notes.md'},
	{source: 'audit-results.json', destination: 'scans/npm/audit-results.json'},
	{source: 'audit-report.txt', destination: 'scans/npm/audit-report.txt'},
	{source: 'outdated-report.txt', destination: 'scans/npm/outdated-report.txt'},
	{source: 'sbom.cdx.json', destination: 'sbom/sbom.cdx.json'}
]);

export const requiredAlternativeArtifactFiles = Object.freeze([
	{
		description: 'Snyk evidence',
		candidates: Object.freeze([
			{source: 'snyk-report.json', destination: 'scans/snyk/snyk-report.json'},
			{source: 'snyk-export-error.txt', destination: 'scans/snyk/snyk-export-error.txt'}
		])
	}
]);

export const futureArtifactPaths = Object.freeze([
	'optional/security-summary.pdf',
	'optional/metadata.json',
	'optional/checksums.sha256'
]);

export function normalizeRelativePath(filePath)
{
	return filePath.split(path.sep).join('/');
}

export function isValidSecurityEvidenceVersion(version)
{
	return typeof version === 'string' && securityEvidenceVersionPattern.test(version);
}

export function assertValidSecurityEvidenceVersion(version)
{
	if (!isValidSecurityEvidenceVersion(version))
	{
		throw new Error(`Invalid security evidence version: expected ${securityEvidenceVersionFormat} (for example 29.0.4).`);
	}
}

export function getSecurityEvidenceArtifactName(version)
{
	assertValidSecurityEvidenceVersion(version);
	return `${securityEvidenceArtifactPrefix}${version}`;
}

export function getRequiredArtifactFilesWithoutSummary()
{
	return requiredArtifactFiles.filter((file) => file.destination !== securitySummaryRelativePath);
}

export function getOrderedArtifactPaths()
{
	return [
		securitySummaryRelativePath,
		...getRequiredArtifactFilesWithoutSummary().map((file) => file.destination),
		...requiredAlternativeArtifactFiles.flatMap((fileGroup) => fileGroup.candidates.map((candidate) => candidate.destination))
	];
}
