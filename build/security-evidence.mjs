import { mkdir, readFile, rm, writeFile } from 'fs/promises';
import { dirname, join, resolve } from 'path';
import { pathToFileURL } from 'url';

const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const SEVERITIES = ['info', 'low', 'moderate', 'high', 'critical'];
const SNYK_SEVERITIES = ['low', 'medium', 'high', 'critical'];
const COMPONENT_TYPES = new Set(['application', 'framework', 'library', 'container', 'platform',
    'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model',
    'data', 'cryptographic-asset']);
const STATUS_FIELDS = ['npmAuditJson', 'npmAuditText', 'npmOutdated', 'snyk', 'sbom'];

function isObject(value)
{
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function escapeHtml(value)
{
    return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

async function loadSourceFile(sourceDir, name)
{
    try
    {
        return { name, text: await readFile(join(sourceDir, name), 'utf8') };
    }
    catch (error)
    {
        if (error.code === 'ENOENT')
        {
            return { name };
        }

        throw error;
    }
}

function parseJson(file, errors)
{
    if (file.text === undefined)
    {
        errors.push(`Missing ${file.name}`);
        return undefined;
    }

    try
    {
        return JSON.parse(file.text);
    }
    catch (error)
    {
        if (error instanceof SyntaxError)
        {
            errors.push(`${file.name} is not valid JSON`);
            return undefined;
        }

        throw error;
    }
}

function validateStatus(status, errors)
{
    if (!isObject(status))
    {
        errors.push('scan-status.json must contain an object');
        return {};
    }

    const result = {};

    for (const field of STATUS_FIELDS)
    {
        if (!Number.isSafeInteger(status[field]) || status[field] < 0)
        {
            errors.push(`scan-status.json ${field} must be a non-negative integer`);
        }
        else
        {
            result[field] = status[field];
        }
    }

    return result;
}

function validateAudit(audit, errors)
{
    const counts = audit?.metadata?.vulnerabilities;

    if (!isObject(audit) || !isObject(audit.metadata) || !isObject(counts))
    {
        errors.push('audit-results.json does not contain npm audit vulnerability counts');
        return undefined;
    }

    for (const field of [...SEVERITIES, 'total'])
    {
        if (!Number.isSafeInteger(counts[field]) || counts[field] < 0)
        {
            errors.push(`audit-results.json ${field} count must be a non-negative integer`);
            return undefined;
        }
    }

    const total = SEVERITIES.reduce((sum, field) => sum + counts[field], 0);

    if (counts.total !== total)
    {
        errors.push('audit-results.json total does not match its severity counts');
        return undefined;
    }

    return counts;
}

function validateSnyk(report, errors)
{
    if (!isObject(report) || typeof report.ok !== 'boolean' || !Array.isArray(report.vulnerabilities))
    {
        errors.push('snyk-report.json does not contain a valid Snyk result');
        return undefined;
    }

    for (const vulnerability of report.vulnerabilities)
    {
        if (!isObject(vulnerability) || !SNYK_SEVERITIES.includes(vulnerability.severity))
        {
            errors.push('snyk-report.json contains an invalid vulnerability');
            return undefined;
        }
    }

    return report;
}

function validateSbom(sbom, errors)
{
    if (!isObject(sbom) || sbom.bomFormat !== 'CycloneDX' ||
        sbom.specVersion !== '1.6' || !Array.isArray(sbom.components) ||
        !sbom.components.every((component) => isObject(component) &&
            COMPONENT_TYPES.has(component.type) &&
            typeof component.name === 'string' && component.name.trim() !== ''))
    {
        errors.push('sbom.cdx.json does not contain a valid CycloneDX BOM');
        return undefined;
    }

    return sbom;
}

function contextFromEnvironment()
{
    return {
        repository: process.env.GITHUB_REPOSITORY,
        workflow: process.env.GITHUB_WORKFLOW,
        runId: process.env.GITHUB_RUN_ID,
        ref: process.env.GITHUB_REF,
        commit: process.env.GITHUB_SHA
    };
}

function validateContext(context, errors)
{
    if (!isObject(context))
    {
        errors.push('GitHub context must contain an object');
        context = {};
    }

    const result = {};
    const repositoryParts = typeof context.repository === 'string' ? context.repository.split('/') : [];
    const validOwner = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
    const validRepository = /^[A-Za-z0-9._-]{1,100}$/;

    if (repositoryParts.length !== 2 || !validOwner.test(repositoryParts[0]) ||
        !validRepository.test(repositoryParts[1]) || ['.', '..'].includes(repositoryParts[1]))
    {
        errors.push('GITHUB_REPOSITORY must use owner/repository format');
    }
    else
    {
        result.repository = context.repository;
    }

    const fields = [['workflow', 'GITHUB_WORKFLOW'], ['ref', 'GITHUB_REF']];

    for (const [field, environmentName] of fields)
    {
        if (typeof context[field] !== 'string' || context[field].trim() === '')
        {
            errors.push(`${environmentName} must not be empty`);
        }
        else
        {
            result[field] = context[field];
        }
    }

    if (typeof context.runId !== 'string' || !/^\d+$/.test(context.runId))
    {
        errors.push('GITHUB_RUN_ID must contain digits only');
    }
    else
    {
        result.runId = context.runId;
    }

    if (typeof context.commit !== 'string' || !/^[0-9a-f]{40}$/i.test(context.commit))
    {
        errors.push('GITHUB_SHA must contain a 40-character commit hash');
    }
    else
    {
        result.commit = context.commit;
    }

    return result;
}

function checkExitCodes(status, auditCounts, snykReport, hasDiagnostic, errors)
{
    if (auditCounts !== undefined)
    {
        const expected = auditCounts.total === 0 ? 0 : 1;

        if (status.npmAuditJson !== undefined && status.npmAuditJson !== expected)
        {
            errors.push(`npm audit JSON exit code must be ${expected}`);
        }

        if (status.npmAuditText !== undefined && status.npmAuditText !== expected)
        {
            errors.push(`npm audit text exit code must be ${expected}`);
        }
    }

    if (status.npmOutdated !== undefined && ![0, 1].includes(status.npmOutdated))
    {
        errors.push('npm outdated ended with a technical error');
    }

    if (status.sbom !== undefined && status.sbom !== 0)
    {
        errors.push('SBOM generation ended with a technical error');
    }

    if (status.snyk === undefined)
    {
        return;
    }

    if (snykReport !== undefined)
    {
        const expected = snykReport.vulnerabilities.length === 0 ? 0 : 1;
        const consistent = expected === 0 ? snykReport.ok === true : snykReport.ok === false;

        if (!consistent || status.snyk !== expected)
        {
            errors.push('Snyk result and exit code are inconsistent');
        }
    }
    else if (hasDiagnostic && [0, 1].includes(status.snyk))
    {
        errors.push('A Snyk diagnostic requires a technical exit code');
    }
    else if (hasDiagnostic)
    {
        errors.push('Snyk ended with a technical error');
    }
}

function renderSummary(version, status, errors, auditCounts, snykReport, sbom, context, links)
{
    const npmCounts = SEVERITIES.map((severity) =>
        `<tr><th>${severity}</th><td>${auditCounts?.[severity] ?? '&mdash;'}</td></tr>`).join('');
    const snykCounts = Object.fromEntries(SNYK_SEVERITIES.map((severity) => [severity, 0]));

    for (const vulnerability of snykReport?.vulnerabilities ?? [])
    {
        snykCounts[vulnerability.severity] += 1;
    }

    const snykTotal = snykReport?.vulnerabilities.length;
    const snykRows = [...SNYK_SEVERITIES, 'total'].map((severity) =>
        `<tr><th>${severity}</th><td>${snykReport === undefined ? '&mdash;' :
            severity === 'total' ? snykTotal : snykCounts[severity]}</td></tr>`).join('');
    const errorRows = errors.map((error) => `<li>${escapeHtml(error)}</li>`).join('');
    const linkRows = links.map(({ href, label }) =>
        `<li><a href="${href}">${escapeHtml(label)}</a></li>`).join('');
    const contextValue = (value) => escapeHtml(value ?? 'Unavailable');
    const riskSection = status === 'blocked' ? `<ul>${errorRows}</ul>` :
        status === 'review-required' ?
            `<p>Snyk reported ${snykTotal} finding${snykTotal === 1 ? '' : 's'}. Review is required before release.</p>` :
            '<p>No blocking conditions were found.</p>';

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security evidence for v${escapeHtml(version)}</title>
<style>
body{color:#222;font:15px/1.5 Arial,sans-serif;margin:2rem auto;max-width:760px;padding:0 1rem}h1{font-size:1.6rem}h2{font-size:1.15rem;margin-top:2rem}.status{border-left:5px solid #777;padding:.7rem 1rem;text-transform:uppercase}.ready{border-color:#16833f}.review-required{border-color:#ba7100}.blocked{border-color:#b42318}table{border-collapse:collapse}th,td{border:1px solid #bbb;padding:.35rem .7rem;text-align:left}code{font-size:.95em}a{color:#075ea8}
</style>
</head>
<body>
<h1>Security evidence for v${escapeHtml(version)}</h1>
<p class="status ${status}"><strong>Status:</strong> ${status}</p>
<h2>Run context</h2>
<table><tbody>
<tr><th>Repository</th><td><code>${contextValue(context.repository)}</code></td></tr>
<tr><th>Workflow</th><td>${contextValue(context.workflow)}</td></tr>
<tr><th>Run ID</th><td>${contextValue(context.runId)}</td></tr>
<tr><th>Git ref</th><td><code>${contextValue(context.ref)}</code></td></tr>
<tr><th>Commit</th><td><code>${contextValue(context.commit)}</code></td></tr>
</tbody></table>
<h2>npm audit</h2>
<table><tbody>${npmCounts}</tbody></table>
<h2>Snyk findings</h2>
<table><tbody>${snykRows}</tbody></table>
<h2>SBOM</h2>
<table><tbody>
<tr><th>Specification</th><td>${escapeHtml(sbom?.specVersion ?? 'Unavailable')}</td></tr>
<tr><th>Components</th><td>${sbom?.components.length ?? '&mdash;'}</td></tr>
</tbody></table>
<h2>Risk assessment</h2>
${riskSection}
<h2>Evidence files</h2>
<ul>${linkRows}</ul>
</body>
</html>
`;
}

async function writeArtifact(root, relativePath, text)
{
    const destination = join(root, relativePath);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, text);
}

export async function packageSecurityEvidence({ version, sourceDir, outputDir, context })
{
    if (!VERSION_PATTERN.test(version ?? ''))
    {
        throw new Error('Version must use X.Y.Z format');
    }

    if (typeof sourceDir !== 'string' || sourceDir === '' || typeof outputDir !== 'string' || outputDir === '')
    {
        throw new Error('Source and output directories are required');
    }

    sourceDir = resolve(sourceDir);
    outputDir = resolve(outputDir);

    const files = {};
    const names = ['release-notes.md', 'audit-results.json', 'audit-report.txt',
        'outdated-report.txt', 'scan-status.json', 'snyk-report.json',
        'snyk-export-error.txt', 'sbom.cdx.json'];

    for (const name of names)
    {
        files[name] = await loadSourceFile(sourceDir, name);
    }

    const errors = [];
    const evidenceContext = validateContext(context ?? contextFromEnvironment(), errors);
    const statusData = parseJson(files['scan-status.json'], errors);
    const status = statusData === undefined ? {} : validateStatus(statusData, errors);
    const audit = parseJson(files['audit-results.json'], errors);
    const auditCounts = audit === undefined ? undefined : validateAudit(audit, errors);
    const sbom = parseJson(files['sbom.cdx.json'], errors);
    const validatedSbom = sbom === undefined ? undefined : validateSbom(sbom, errors);

    const hasSnykReport = files['snyk-report.json'].text !== undefined;
    const hasSnykDiagnostic = files['snyk-export-error.txt'].text !== undefined;
    let snykReport;
    let snykSource;

    if (hasSnykReport === hasSnykDiagnostic)
    {
        errors.push('Exactly one Snyk report or diagnostic is required');

        if (hasSnykReport)
        {
            snykSource = status.snyk !== undefined && ![0, 1].includes(status.snyk) ?
                'snyk-export-error.txt' : 'snyk-report.json';
        }
    }
    else
    {
        snykSource = hasSnykReport ? 'snyk-report.json' : 'snyk-export-error.txt';
    }

    if (snykSource === 'snyk-report.json')
    {
        const snyk = parseJson(files['snyk-report.json'], errors);
        snykReport = snyk === undefined ? undefined : validateSnyk(snyk, errors);
    }
    else if (snykSource === 'snyk-export-error.txt' && files['snyk-export-error.txt'].text.trim() === '')
    {
        errors.push('snyk-export-error.txt must not be empty');
    }

    if (files['release-notes.md'].text === undefined)
    {
        errors.push('Missing release-notes.md');
    }
    else if (files['release-notes.md'].text.trim() === '')
    {
        errors.push('release-notes.md must not be empty');
    }

    if (files['audit-report.txt'].text === undefined)
    {
        errors.push('Missing audit-report.txt');
    }
    else if (files['audit-report.txt'].text.trim() === '')
    {
        errors.push('audit-report.txt must not be empty');
    }

    if (files['outdated-report.txt'].text === undefined)
    {
        errors.push('Missing outdated-report.txt');
    }

    checkExitCodes(status, auditCounts, snykReport, snykSource === 'snyk-export-error.txt', errors);

    if (auditCounts !== undefined && (auditCounts.high > 0 || auditCounts.critical > 0))
    {
        errors.push('npm audit reports high or critical vulnerabilities');
    }

    const packDir = join(outputDir, `security-evidence-pack-v${version}`);
    await rm(packDir, { recursive: true, force: true });
    await mkdir(packDir, { recursive: true });

    const artifactFiles = [
        ['release-notes.md', 'release/release-notes.md', 'Release notes'],
        ['audit-results.json', 'scans/npm/audit-results.json', 'npm audit JSON'],
        ['audit-report.txt', 'scans/npm/audit-report.txt', 'npm audit report'],
        ['outdated-report.txt', 'scans/npm/outdated-report.txt', 'npm outdated report'],
        ['sbom.cdx.json', 'sbom/sbom.cdx.json', 'CycloneDX SBOM']
    ];

    if (snykSource === 'snyk-report.json')
    {
        artifactFiles.push(['snyk-report.json', 'scans/snyk/snyk-report.json', 'Snyk report']);
    }
    else if (snykSource === 'snyk-export-error.txt')
    {
        artifactFiles.push(['snyk-export-error.txt', 'scans/snyk/snyk-export-error.txt', 'Snyk diagnostic']);
    }

    const links = [];

    for (const [sourceName, relativePath, label] of artifactFiles)
    {
        if (files[sourceName].text !== undefined)
        {
            await writeArtifact(packDir, relativePath, files[sourceName].text);
            links.push({ href: `../${relativePath}`, label });
        }
    }

    const resultStatus = errors.length > 0 ? 'blocked' :
        snykReport.vulnerabilities.length > 0 ? 'review-required' : 'ready';
    await writeArtifact(packDir, 'summary/security-summary.html',
        renderSummary(version, resultStatus, errors, auditCounts, snykReport, validatedSbom,
            evidenceContext, links));

    return { status: resultStatus, outputDir: packDir, errors };
}

function parseArguments(args)
{
    const options = {};
    const names = new Map([
        ['--version', 'version'],
        ['--source-dir', 'sourceDir'],
        ['--output-dir', 'outputDir']
    ]);

    for (let index = 0; index < args.length; index += 2)
    {
        const key = names.get(args[index]);
        const value = args[index + 1];

        if (key === undefined || value === undefined || value.startsWith('--') || options[key] !== undefined)
        {
            throw new Error('Usage: security-evidence.mjs --version X.Y.Z --source-dir DIR --output-dir DIR');
        }

        options[key] = value;
    }

    return options;
}

if (process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
{
    try
    {
        const result = await packageSecurityEvidence(parseArguments(process.argv.slice(2)));
        console.log(`Security evidence: ${result.status} (${result.outputDir})`);
        process.exitCode = result.status === 'blocked' ? 1 : 0;
    }
    catch (error)
    {
        console.error(error.message);
        process.exitCode = 1;
    }
}
