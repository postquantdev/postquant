import chalk from 'chalk';
import type { GradedResult, RiskLevel, Grade } from '../types/index.js';

const VERSION = '0.1.1';

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

function protocolLabel(risk: RiskLevel): string {
  switch (risk) {
    case 'critical':
      return chalk.red('🔴 Legacy (Insecure)');
    case 'moderate':
      return chalk.yellow('🟡 Aging');
    case 'safe':
      return chalk.green('🟢 Current');
  }
}

function gradeColor(g: Grade): string {
  if (g.startsWith('A')) return chalk.green.bold(g);
  if (g.startsWith('B')) return chalk.yellow.bold(g);
  return chalk.red.bold(g);
}

export function formatTerminal(result: GradedResult): string {
  const lines: string[] = [];

  const bar = '━'.repeat(48);

  lines.push('');
  lines.push(
    chalk.bold(`🔐 PostQuant v${VERSION} — Quantum Readiness Scanner`),
  );
  lines.push(chalk.dim(bar));
  lines.push('');
  lines.push(`  Target: ${chalk.bold(`${result.host}:${result.port}`)}`);
  lines.push('');
  lines.push(`  Overall Grade:  ${gradeColor(result.grade)}`);
  lines.push('');

  const certFinding = result.findings.find((f) => f.component === 'certificate');
  if (certFinding) {
    lines.push('  Certificate');
    const algoStr = certFinding.curve
      ? `${certFinding.algorithm} ${certFinding.curve}`
      : certFinding.keySize
        ? `${certFinding.algorithm}-${certFinding.keySize}`
        : certFinding.algorithm;
    lines.push(
      `    Algorithm:    ${algoStr.padEnd(20)} ${riskIcon(certFinding.risk)}`,
    );
  }

  const protocolFinding = result.findings.find((f) => f.component === 'protocol');
  const kxFinding = result.findings.find((f) => f.component === 'keyExchange');
  const cipherFinding = result.findings.find((f) => f.component === 'cipher');
  const hashFinding = result.findings.find((f) => f.component === 'hash');

  lines.push('');
  lines.push('  Connection');
  if (protocolFinding) {
    lines.push(
      `    Protocol:     ${protocolFinding.algorithm.padEnd(20)} ${protocolLabel(protocolFinding.risk)}`,
    );
  }
  if (kxFinding) {
    lines.push(
      `    Key Exchange: ${kxFinding.algorithm.padEnd(20)} ${riskIcon(kxFinding.risk)}`,
    );
  }
  if (cipherFinding) {
    lines.push(
      `    Cipher:       ${cipherFinding.algorithm.padEnd(20)} ${riskIcon(cipherFinding.risk)}`,
    );
  }
  if (hashFinding) {
    const hashLabel =
      cipherFinding?.algorithm.includes('GCM') ||
      cipherFinding?.algorithm.includes('CHACHA')
        ? 'AEAD'
        : hashFinding.algorithm;
    lines.push(
      `    MAC:          ${hashLabel.padEnd(20)} ${riskIcon(hashFinding.risk)}`,
    );
  }

  lines.push('');
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

  if (result.migrationNotes.length > 0) {
    lines.push('');
    lines.push('  Migration Notes');
    for (const note of result.migrationNotes) {
      lines.push(`    • ${note}`);
    }
    lines.push(
      chalk.dim(
        '    • NIST Timeline: Current algorithms deprecated 2030, disallowed 2035',
      ),
    );
  }

  lines.push('');
  lines.push(chalk.dim(bar));
  lines.push('');

  return lines.join('\n');
}
