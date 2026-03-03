import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import chalk from 'chalk';
import type { CodeGradedResult, FileBreakdown, RiskLevel, Grade } from '../types/index.js';

function getVersion(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf-8'),
    );
    return pkg.version;
  } catch {
    return '0.2.0';
  }
}

export interface CodeTerminalOptions {
  verbose?: boolean;
  noMigration?: boolean;
}

function riskIcon(risk: RiskLevel): string {
  switch (risk) {
    case 'critical':
      return chalk.red('🔴 Quantum Vulnerable');
    case 'moderate':
      return chalk.yellow('🟡 Moderate Risk');
    case 'safe':
      return chalk.green('🟢 Quantum Safe');
  }
}

function gradeColor(g: Grade): string {
  if (g.startsWith('A')) return chalk.green.bold(g);
  if (g.startsWith('B')) return chalk.yellow.bold(g);
  return chalk.red.bold(g);
}

export function formatCodeTerminal(
  result: CodeGradedResult,
  options: CodeTerminalOptions = {},
): string {
  const { verbose = false, noMigration = false } = options;
  const lines: string[] = [];
  const bar = '━'.repeat(48);

  lines.push('');
  lines.push(
    chalk.bold(`🔐 PostQuant v${getVersion()} — Code Scanner`),
  );
  lines.push(chalk.dim(bar));
  lines.push('');
  lines.push(`  Scan Root: ${chalk.bold(result.scanRoot)}`);
  lines.push('');
  lines.push(`  Overall Grade:  ${gradeColor(result.grade)}`);
  lines.push('');

  // Stats
  lines.push('  Stats');
  lines.push(`    Files scanned:      ${result.summary.filesScanned}`);
  lines.push(`    Files with findings: ${result.summary.filesWithFindings}`);
  lines.push('');

  // Summary counts
  lines.push('  Summary');
  if (result.summary.critical > 0) {
    lines.push(
      chalk.red(
        `    🔴 ${result.summary.critical} quantum-vulnerable finding${result.summary.critical > 1 ? 's' : ''}`,
      ),
    );
  }
  if (result.summary.moderate > 0) {
    lines.push(
      chalk.yellow(
        `    🟡 ${result.summary.moderate} moderate-risk finding${result.summary.moderate > 1 ? 's' : ''}`,
      ),
    );
  }
  if (result.summary.safe > 0) {
    lines.push(
      chalk.green(
        `    🟢 ${result.summary.safe} quantum-safe finding${result.summary.safe > 1 ? 's' : ''}`,
      ),
    );
  }
  if (result.summary.total === 0) {
    lines.push(
      chalk.green('    No quantum-vulnerable cryptography detected.'),
    );
  }
  lines.push('');

  // Per-file breakdown
  const filesToShow = verbose
    ? result.fileBreakdown
    : result.fileBreakdown.filter(
        (fb) => fb.criticalCount > 0 || fb.moderateCount > 0,
      );

  if (filesToShow.length > 0) {
    lines.push('  Findings');
    lines.push('');

    for (const fb of filesToShow) {
      lines.push(
        `  ${chalk.bold(fb.file)} ${chalk.dim(`(${fb.language})`)}`,
      );

      const findingsToShow = verbose
        ? fb.findings
        : fb.findings.filter((f) => f.risk !== 'safe');

      for (const f of findingsToShow) {
        lines.push(
          `    L${f.line}: ${f.algorithm.padEnd(16)} ${riskIcon(f.risk)}`,
        );
      }
      lines.push('');
    }
  }

  // Migration notes
  if (!noMigration && result.migrationNotes.length > 0) {
    lines.push('  Migration Notes');
    for (const note of result.migrationNotes) {
      lines.push(`    • ${note}`);
    }
    lines.push(
      chalk.dim(
        '    • NIST Timeline: Current algorithms deprecated 2030, disallowed 2035',
      ),
    );
    lines.push('');
  }

  lines.push(chalk.dim(bar));
  lines.push('');

  return lines.join('\n');
}
