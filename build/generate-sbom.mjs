import { spawn } from 'child_process';
import { mkdir } from 'fs/promises';
import os from 'os';
import path from 'path';

const CYCLONEDX_PACKAGE = '@cyclonedx/cyclonedx-npm@4.2.1';

function parseOutput(args)
{
    if (args.length !== 2 || args[0] !== '--output' || args[1].length === 0)
    {
        throw new Error('Usage: npm run generate-sbom -- --output <absolute temporary path>');
    }

    if (!path.isAbsolute(args[1]))
    {
        throw new Error('The SBOM output path must be absolute');
    }

    return path.resolve(args[1]);
}

function assertTemporaryOutput(outputFile)
{
    const tempDir = path.resolve(process.env.RUNNER_TEMP || os.tmpdir());
    const relativePath = path.relative(tempDir, outputFile);

    if (relativePath === '' || relativePath === '..' ||
        relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath))
    {
        throw new Error(`The SBOM output path must be inside ${tempDir}`);
    }
}

function generateSbom(outputFile)
{
    const npmCliPath = process.env.npm_execpath;

    if (!npmCliPath)
    {
        throw new Error('Run SBOM generation through "npm run generate-sbom"');
    }

    const args = [
        npmCliPath,
        'exec',
        '--yes',
        `--package=${CYCLONEDX_PACKAGE}`,
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

    return new Promise((resolve, reject) =>
    {
        const child = spawn(process.execPath, args, { stdio: 'inherit' });

        child.once('error', reject);
        child.once('close', (exitCode, signal) =>
        {
            if (signal)
            {
                reject(new Error(`SBOM generation terminated by signal ${signal}`));
            }
            else
            {
                resolve(exitCode ?? 1);
            }
        });
    });
}

async function main()
{
    const outputFile = parseOutput(process.argv.slice(2));
    assertTemporaryOutput(outputFile);
    await mkdir(path.dirname(outputFile), { recursive: true });

    process.exitCode = await generateSbom(outputFile);
}

main().catch((error) =>
{
    console.error(error.message);
    process.exitCode = 1;
});
