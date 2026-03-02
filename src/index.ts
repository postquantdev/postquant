#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import type { OutputFormat, Grade } from './types/index.js';

const VALID_GRADES: Grade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

const program = new Command();

program
  .name('postquant')
  .description('Scan TLS endpoints for quantum-vulnerable cryptography')
  .version('0.1.1');

program
  .command('scan')
  .description('Scan one or more TLS endpoints for quantum readiness')
  .argument('[hosts...]', 'Hostnames to scan (with optional :port)')
  .option('-f, --format <format>', 'Output format (terminal, json)', 'terminal')
  .option('--file <path>', 'Read hosts from file (one per line)')
  .option('--timeout <ms>', 'Connection timeout in milliseconds', '10000')
  .option('--verbose', 'Show raw TLS handshake details', false)
  .option(
    '--fail-grade <grade>',
    'Exit non-zero at this grade or worse',
    'C',
  )
  .action(async (hosts: string[], opts) => {
    const format = opts.format as OutputFormat;
    if (format !== 'terminal' && format !== 'json') {
      console.error(`Invalid format: ${format}. Use 'terminal' or 'json'.`);
      process.exit(1);
    }

    const failGrade = opts.failGrade as Grade;
    if (!VALID_GRADES.includes(failGrade)) {
      console.error(
        `Invalid fail-grade: ${failGrade}. Use one of: ${VALID_GRADES.join(', ')}`,
      );
      process.exit(1);
    }

    const exitCode = await scanCommand(hosts, {
      format,
      timeout: parseInt(opts.timeout, 10),
      verbose: opts.verbose,
      failGrade,
      file: opts.file,
    });

    process.exit(exitCode);
  });

program.parse();
