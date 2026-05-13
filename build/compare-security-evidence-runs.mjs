import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {isDeepStrictEqual, parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';

function uniqueSorted(values)
{
	return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function getRunLabel(analysis, index)
{
	return analysis?.externalRun?.label || `Run ${index + 1}`;
}

function getRunUrl(analysis)
{
	return analysis?.externalRun?.runUrl || analysis?.summary?.context?.runUrl || null;
}

function getRunTypeLabel(analysis)
{
	if (analysis?.externalRun?.dryRun === true)
	{
		return 'Dry-Run';
	}

	if (analysis?.externalRun?.dryRun === false)
	{
		return 'Real-Run';
	}

	return 'Unclassified';
}

function getEvidenceReference(analyses)
{
	return analyses
		.map((analysis, index) =>
		{
			const label = getRunLabel(analysis, index);
			const runUrl = getRunUrl(analysis);
			return runUrl ? `${label} (${runUrl})` : label;
		})
		.join(', ');
}

function collectDifferencePaths(reference, candidate, prefix = '')
{
	if (isDeepStrictEqual(reference, candidate))
	{
		return [];
	}

	if (Array.isArray(reference) && Array.isArray(candidate))
	{
		if (reference.length !== candidate.length)
		{
			return [prefix || '(root)'];
		}

		return reference.flatMap((value, index) =>
			collectDifferencePaths(value, candidate[index], prefix ? `${prefix}[${index}]` : `[${index}]`)
		);
	}

	if (reference && typeof reference === 'object' && candidate && typeof candidate === 'object')
	{
		const keys = uniqueSorted([...Object.keys(reference), ...Object.keys(candidate)]);
		return keys.flatMap((key) =>
			collectDifferencePaths(reference[key], candidate[key], prefix ? `${prefix}.${key}` : key)
		);
	}

	return [prefix || '(root)'];
}

function summarizeRatings(passedRuns, totalRuns, successText, failureText)
{
	if (passedRuns === totalRuns)
	{
		return {
			rating: 'Erfuellt',
			actual: successText
		};
	}

	if (passedRuns > 0)
	{
		return {
			rating: 'Teilweise erfuellt',
			actual: `${passedRuns}/${totalRuns} Runs erfuellen das Kriterium; ${failureText}`
		};
	}

	return {
		rating: 'Nicht erfuellt',
		actual: failureText
	};
}

function buildRunMatrix(analyses)
{
	return analyses.map((analysis, index) => ({
		label: getRunLabel(analysis, index),
		type: getRunTypeLabel(analysis),
		runUrl: getRunUrl(analysis),
		artifactName: analysis?.artifact?.name || null,
		summaryStatus: analysis?.summary?.status || null,
		completenessPassed: Boolean(analysis?.completeness?.requiredPathsPresent && analysis?.completeness?.exactlyOneSnykEvidence),
		formalValidationPassed: Boolean(analysis?.formalValidation?.passed),
		traceabilityPassed: Boolean(analysis?.traceability?.passed),
		branchName: analysis?.externalRun?.branchName || null,
		prUrl: analysis?.externalRun?.prUrl || null
	}));
}

function buildCriteria(analyses, reproducibility, productPath)
{
	const completenessPassedRuns = analyses.filter((analysis) => analysis?.completeness?.requiredPathsPresent && analysis?.completeness?.exactlyOneSnykEvidence).length;
	const formalValidationPassedRuns = analyses.filter((analysis) => analysis?.formalValidation?.passed).length;
	const traceabilityPassedRuns = analyses.filter((analysis) => analysis?.traceability?.passed).length;

	const completenessSummary = summarizeRatings(
		completenessPassedRuns,
		analyses.length,
		`${analyses.length}/${analyses.length} Runs enthalten alle Pflichtdateien und genau einen Snyk-Nachweis.`,
		`${analyses.length - completenessPassedRuns} Run(s) haben fehlende Pflichtdateien oder mehrere/keine Snyk-Nachweise.`
	);
	const formalValidationSummary = summarizeRatings(
		formalValidationPassedRuns,
		analyses.length,
		`${analyses.length}/${analyses.length} Runs bestehen die formale Artefaktvalidierung ohne Fehler.`,
		`${analyses.length - formalValidationPassedRuns} Run(s) haben formale Validierungsfehler.`
	);
	const traceabilitySummary = summarizeRatings(
		traceabilityPassedRuns,
		analyses.length,
		`${analyses.length}/${analyses.length} Runs lassen sich aus Summary, Artefakt und externer Metadatei eindeutig zurueckverfolgen.`,
		`${analyses.length - traceabilityPassedRuns} Run(s) weisen Traceability-Luecken auf.`
	);

	return [
		{
			criterion: 'Vollstaendigkeit',
			target: 'Alle erfolgreichen Runs enthalten 100% Pflichtdateien in der Sollstruktur und genau einen Snyk-Nachweis.',
			actual: completenessSummary.actual,
			rating: completenessSummary.rating,
			evidence: getEvidenceReference(analyses),
			interpretation: completenessSummary.rating === 'Erfuellt'
				? 'Die Artefaktstruktur ist ueber die Kampagne hinweg stabil und vollstaendig.'
				: 'Mindestens ein Run verletzt die definierte Pflichtstruktur und muss im Artefaktinventar nachuntersucht werden.'
		},
		{
			criterion: 'Formalkorrektheit',
			target: 'Audit-JSON, Snyk-Nachweis, SBOM und HTML-Summary sind parsebar und erfuellen die Vertragsregeln.',
			actual: formalValidationSummary.actual,
			rating: formalValidationSummary.rating,
			evidence: getEvidenceReference(analyses),
			interpretation: formalValidationSummary.rating === 'Erfuellt'
				? 'Die technischen Nachweise sind konsistent lesbar und koennen automatisiert weiterverarbeitet werden.'
				: 'Mindestens ein Artefakt verletzt Parse- oder Vertragsregeln; die betroffenen Validierungsfehler muessen bereinigt werden.'
		},
		{
			criterion: 'Reproduzierbarkeit',
			target: 'Dry-Run A/B/C liefern identische Invarianten; Unterschiede sind nur in volatilen Feldern zulaessig.',
			actual: reproducibility.actual,
			rating: reproducibility.rating,
			evidence: reproducibility.evidence,
			interpretation: reproducibility.rating === 'Erfuellt'
				? 'Die Dry-Runs erzeugen konsistente Kernaussagen und bestaetigen den reproduzierbaren Evidence-Pack-Pfad.'
				: 'Mindestens ein Dry-Run weicht in den normalisierten Kerndaten ab; die aufgefuehrten Differenzen muessen erklaert werden.'
		},
		{
			criterion: 'Nachvollziehbarkeit',
			target: 'Version, Commit, Ref, drawio-Ref, Run-ID/-URL und Artefaktname sind konsistent verknuepft.',
			actual: traceabilitySummary.actual,
			rating: traceabilitySummary.rating,
			evidence: getEvidenceReference(analyses),
			interpretation: traceabilitySummary.rating === 'Erfuellt'
				? 'Reviewer koennen jeden Run sauber bis auf Workflow und Artefakt zurueckverfolgen.'
				: 'Die Rueckverfolgbarkeit ist unvollstaendig; fehlende oder widerspruechliche Metadaten muessen ergaenzt werden.'
		},
		{
			criterion: 'Produktivpfad (`dry_run=false`)',
			target: 'Mindestens ein echter Run erzeugt denselben Evidence-Pack-Typ und dokumentiert zusaetzlich Branch und PR.',
			actual: productPath.actual,
			rating: productPath.rating,
			evidence: productPath.evidence,
			interpretation: productPath.rating === 'Erfuellt'
				? 'Der Commit-/Push-/PR-Pfad ist praktisch belegt und ergaenzt die Dry-Run-Serie um einen realen Release-Vorbereitungslauf.'
				: 'Der reale Pfad ist noch nicht ausreichend belegt oder weicht in den Kerndaten vom Dry-Run-Referenzlauf ab.'
		}
	];
}

function buildReproducibilityReport(analyses)
{
	const dryRuns = analyses.filter((analysis) => analysis?.externalRun?.dryRun === true);

	if (dryRuns.length === 0)
	{
		return {
			passed: false,
			rating: 'Nicht erfuellt',
			actual: 'Es wurden keine Dry-Runs zur Reproduzierbarkeitspruefung geliefert.',
			evidence: 'Kein Dry-Run analysiert.',
			referenceLabel: null,
			comparisons: []
		};
	}

	const referenceRun = dryRuns[0];
	const comparisons = dryRuns.slice(1).map((analysis, index) =>
	{
		const differencePaths = collectDifferencePaths(referenceRun.invariants, analysis.invariants);
		return {
			label: getRunLabel(analysis, index + 1),
			matches: differencePaths.length === 0,
			differencePaths
		};
	});
	const failedComparisons = comparisons.filter((comparison) => !comparison.matches);

	if (failedComparisons.length === 0)
	{
		return {
			passed: true,
			rating: 'Erfuellt',
			actual: `${dryRuns.length}/${dryRuns.length} Dry-Runs haben identische Invariant-Sets.`,
			evidence: dryRuns.map((analysis, index) => getRunLabel(analysis, index)).join(', '),
			referenceLabel: getRunLabel(referenceRun, 0),
			comparisons
		};
	}

	return {
		passed: false,
		rating: 'Nicht erfuellt',
		actual: `Abweichungen in ${failedComparisons.length}/${comparisons.length} Vergleich(en): ${failedComparisons.map((comparison) => `${comparison.label} -> ${comparison.differencePaths.join(', ')}`).join('; ')}`,
		evidence: dryRuns.map((analysis, index) => getRunLabel(analysis, index)).join(', '),
		referenceLabel: getRunLabel(referenceRun, 0),
		comparisons
	};
}

function buildProductPathReport(analyses)
{
	const realRuns = analyses.filter((analysis) => analysis?.externalRun?.dryRun === false);
	const dryRuns = analyses.filter((analysis) => analysis?.externalRun?.dryRun === true);
	const referenceRun = dryRuns[0] || analyses[0] || null;

	if (realRuns.length === 0)
	{
		return {
			rating: 'Nicht erfuellt',
			actual: 'Es wurde kein echter `dry_run=false`-Lauf analysiert.',
			evidence: 'Kein Real-Run vorhanden.'
		};
	}

	const failedRealRuns = realRuns.filter((analysis) =>
	{
		const hasBranchAndPr = Boolean(analysis?.externalRun?.branchName) && Boolean(analysis?.externalRun?.prUrl);
		const matchesReference = referenceRun ? isDeepStrictEqual(referenceRun.invariants, analysis.invariants) : true;
		return !(hasBranchAndPr && matchesReference && analysis?.traceability?.passed);
	});

	if (failedRealRuns.length === 0)
	{
		return {
			rating: 'Erfuellt',
			actual: `${realRuns.length}/${realRuns.length} Real-Run(s) dokumentieren Branch und PR und stimmen in den Invarianten mit dem Referenzlauf ueberein.`,
			evidence: realRuns.map((analysis, index) =>
			{
				const label = getRunLabel(analysis, index);
				return `${label} (${analysis.externalRun.branchName}, ${analysis.externalRun.prUrl})`;
			}).join(', ')
		};
	}

	return {
		rating: 'Nicht erfuellt',
		actual: `${failedRealRuns.length}/${realRuns.length} Real-Run(s) fehlen Branch/PR-Metadaten oder weichen in den Invarianten vom Referenzlauf ab.`,
		evidence: failedRealRuns.map((analysis, index) => getRunLabel(analysis, index)).join(', ')
	};
}

export function compareSecurityEvidenceRuns(analyses, options = {})
{
	if (!Array.isArray(analyses) || analyses.length === 0)
	{
		throw new Error('At least one run analysis is required');
	}

	const runMatrix = buildRunMatrix(analyses);
	const reproducibility = buildReproducibilityReport(analyses);
	const productPath = buildProductPathReport(analyses);
	const criteria = buildCriteria(analyses, reproducibility, productPath);

	return {
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		title: options.title || 'Security Evidence Validation Campaign',
		runMatrix,
		reproducibility,
		productPath,
		criteria
	};
}

export function renderSecurityEvidenceComparisonMarkdown(report)
{
	const runRows = report.runMatrix.map((row) =>
		`| ${row.label} | ${row.type} | ${row.summaryStatus || '-'} | ${row.completenessPassed ? 'Ja' : 'Nein'} | ${row.formalValidationPassed ? 'Ja' : 'Nein'} | ${row.traceabilityPassed ? 'Ja' : 'Nein'} | ${row.runUrl || '-'} |`
	).join('\n');
	const criteriaRows = report.criteria.map((criterion) =>
		`| ${criterion.criterion} | ${criterion.target} | ${criterion.actual} | ${criterion.rating} | ${criterion.evidence} |`
	).join('\n');
	const interpretations = report.criteria.map((criterion) =>
		`### ${criterion.criterion}\n${criterion.interpretation}`
	).join('\n\n');

	return `## Run-Matrix

| Run | Typ | Summary-Status | Vollstaendig | Formal valide | Nachvollziehbar | Workflow-URL |
|-----|-----|----------------|-------------|---------------|-----------------|--------------|
${runRows}

## Bewertung

| Kriterium | Soll | Ist | Bewertung | Evidenz |
|-----------|------|-----|-----------|---------|
${criteriaRows}

${interpretations}
`;
}

async function readAnalysisFile(filePath)
{
	return JSON.parse(await readFile(path.resolve(filePath), 'utf8'));
}

function parseCliOptions(argv = process.argv.slice(2))
{
	const {values} = parseArgs({
		args: argv,
		options: {
			'analysis-file': {
				type: 'string',
				multiple: true
			},
			title: {type: 'string'},
			'output-json': {type: 'string'},
			'output-markdown': {type: 'string'}
		},
		strict: true
	});

	return {
		analysisFiles: values['analysis-file'] || [],
		title: values.title,
		outputJson: values['output-json'],
		outputMarkdown: values['output-markdown']
	};
}

export async function main(argv = process.argv.slice(2))
{
	const options = parseCliOptions(argv);

	if (options.analysisFiles.length === 0)
	{
		throw new Error('Missing required option: --analysis-file');
	}

	const analyses = [];

	for (const analysisFile of options.analysisFiles)
	{
		analyses.push(await readAnalysisFile(analysisFile));
	}

	const report = compareSecurityEvidenceRuns(analyses, {
		title: options.title
	});
	const reportJson = JSON.stringify(report, null, 2);
	const reportMarkdown = renderSecurityEvidenceComparisonMarkdown(report);

	if (options.outputJson)
	{
		await writeFile(path.resolve(options.outputJson), reportJson, 'utf8');
		console.log(`Wrote comparison JSON: ${path.resolve(options.outputJson)}`);
	}

	if (options.outputMarkdown)
	{
		await writeFile(path.resolve(options.outputMarkdown), reportMarkdown, 'utf8');
		console.log(`Wrote comparison Markdown: ${path.resolve(options.outputMarkdown)}`);
	}

	if (!options.outputJson && !options.outputMarkdown)
	{
		console.log(reportJson);
	}
}

const entryPoint = process.argv[1] ? path.resolve(process.argv[1]) : '';

if (entryPoint === fileURLToPath(import.meta.url))
{
	main().catch((error) =>
	{
		console.error(error.message);
		process.exitCode = 1;
	});
}
