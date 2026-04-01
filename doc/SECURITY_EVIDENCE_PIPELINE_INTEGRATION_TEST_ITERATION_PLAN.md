# SecProj – Plan für Integrationstests im Workflow (Iterationen)

## Ziel
Dieser Plan beschreibt, wie Integrationstests schrittweise in den draw.io-Workflow für das **Security Evidence Pack** integriert werden.

## Annahmen & Scope
- Fokus: Pipeline-Integration (Build, Evidence-Erzeugung, Validierung, Packaging).
- Nicht-Ziel im MVP: vollständige End-to-End-Abdeckung aller Plattform-Sonderfälle.
- Qualitätstore (Quality Gates) werden iterativ von "warnend" auf "blockierend" umgestellt.

## Iteration 0 – Baseline & Testbarkeit schaffen (1 Sprint)
### Ziel
Test-Harness und reproduzierbare Testdaten etablieren.

### Deliverables
- Testdaten-Fixture für ein minimales Security Evidence Pack.
- CI-Job für Integrationstests (noch nicht blockierend).
- Dokumentation der Soll-/Ist-Schnittstellen zwischen Build-Schritten.

### Testfälle
1. Pipeline kann mit Fixture-Daten erfolgreich laufen.
2. Evidence-Packaging erzeugt erwartete Verzeichnisstruktur.
3. Fehlende optionale Artefakte führen zu Warnung, nicht Abbruch.

### Exit-Kriterien
- Tests laufen stabil in CI auf mindestens einer Zielplattform.
- Flaky-Rate < 5% über 20 Runs.

## Iteration 1 – Kernfluss absichern (1–2 Sprints)
### Ziel
Kritische Artefakte und Validationslogik technisch absichern.

### Deliverables
- Integrationstests für:
  - SBOM-Generierung,
  - Security Summary,
  - Packaging des Evidence Packs.
- Deterministische Assertions (Dateiname, Pflichtfelder, JSON-Schema).

### Testfälle
1. Erfolgsfall: alle Pflichtartefakte vorhanden und valide.
2. Negativfall: manipulierte SBOM wird erkannt.
3. Negativfall: ungültige Metadaten führen zu Pipeline-Fail.

### Exit-Kriterien
- Kritische Tests als blockierendes Quality Gate aktiv.
- Mittlere Laufzeit der Integrationssuite < 10 Minuten.

## Iteration 2 – Release-Workflow-Integration (1 Sprint)
### Ziel
Integrationstests in reale Release-Pfade einhängen.

### Deliverables
- Trigger in Release-Branches/Tags.
- Trennung von "PR-Checks" (schnell) und "Release-Checks" (vollständig).
- Einheitliches Reporting (pass/fail + Artefakt-Links).

### Testfälle
1. PR-Pfad: reduzierte Integrationssuite läuft bei Änderungen an Security-Skripten.
2. Release-Pfad: vollständige Suite inkl. Packaging/Archiv.
3. Wiederanlauf-Szenario: fehlgeschlagener Job kann reproduzierbar rerun werden.

### Exit-Kriterien
- Kein Release ohne grünes Security-Evidence-Gate.
- Vollständige Suite bei 3 aufeinanderfolgenden Releases stabil.

## Iteration 3 – Härtung & Governance (fortlaufend)
### Ziel
Nachweisbarkeit, Audittauglichkeit und Betriebssicherheit erhöhen.

### Deliverables
- Versionierte Testreports als Teil des Evidence Packs.
- Traceability-Matrix (Anforderung → Testfall → Artefakt).
- Eskalationsregeln für Gate-Verstöße (Owner, SLA, Freigabeprozess).

### Testfälle
1. Audit-Readiness: alle Pflichtnachweise sind über Report referenzierbar.
2. Governance-Fall: Override nur mit dokumentierter Freigabe möglich.
3. Regression: bekannte Vorfälle bleiben durch Tests abgedeckt.

### Exit-Kriterien
- Audit-Check ohne "Major Findings".
- Traceability für 100% MVP-Pflichtkriterien.

## Definition of Done pro Iteration
- Testfälle in CI automatisiert.
- Klare Owner für fehlschlagende Tests.
- Dokumentierte Runbooks für Fehleranalyse.
- Metriken erhoben und im Teamreview bewertet.

## Metriken zur Steuerung
- Pass-Rate Integrationssuite.
- Flaky-Rate.
- Mean Time to Fix (MTTFix) bei Gate-Fehlern.
- Laufzeit (p50/p95) der Suite.
- Abdeckungsgrad der MVP-Pflichtanforderungen durch Integrationstests.

## Risiken & Gegenmaßnahmen
- **Flaky Tests durch externe Abhängigkeiten** → Mocking/Fixture-Strategie, Retry nur kontrolliert.
- **Zu lange Laufzeiten** → Testpyramide, Splitting in Fast/Full-Suite.
- **Unklare Verantwortlichkeit** → feste Ownership pro Testdomäne.
- **Schema-/Formatdrift** → versionierte Schemas + Kompatibilitätstests.

## Konkrete nächste Schritte
1. Iteration-0-Backlog als Issues schneiden (Fixture, CI-Job, Basis-Tests).
2. Kritische Pflichtkriterien aus MVP explizit auf Testfälle mappen.
3. Gate-Strategie mit Stakeholdern abstimmen (Warnung vs. Blocker je Iteration).
4. Pilot auf einem Release-Zweig durchführen und Metriken baseline'n.
