#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { analyzeCommand } from './commands/analyze.js';
import type { OutputFormat, AnalyzeOutputFormat, BaseGrade, Language } from './types/index.js';

const VALID_GRADES: BaseGrade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];
const VALID_ANALYZE_FORMATS: AnalyzeOutputFormat[] = ['terminal', 'json', 'sarif', 'cbom'];
const VALID_LANGUAGES: Language[] = ['python', 'javascript', 'go', 'java', 'c', 'rust'];

const program = new Command();

program
  .name('postquant')
  .description('Scan TLS endpoints and source code for quantum-vulnerable cryptography')
  .version('0.7.0');

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

    const failGrade = opts.failGrade as BaseGrade;
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

program
  .command('analyze')
  .description('Scan source code for quantum-vulnerable cryptography')
  .argument('<path>', 'Directory or file to scan')
  .option('-f, --format <format>', 'Output format (terminal, json, sarif, cbom)', 'terminal')
  .option('-l, --language <language>', 'Filter by language (python, javascript, go, java)')
  .option('--fail-grade <grade>', 'Exit non-zero at this grade or worse', 'C')
  .option('--ignore <patterns...>', 'Glob patterns to exclude')
  .option('--ignore-file <path>', 'File with ignore patterns', '.postquantignore')
  .option('--max-files <count>', 'Maximum files to scan', '10000')
  .option('--verbose', 'Show all findings including safe ones', false)
  .option('--no-migration', 'Hide migration recommendations')
  .option('--show-all', 'Show all findings including low and informational risk')
  .option('--no-context', 'Skip risk assessment, use raw pattern matching only')
  .option('--no-ast', 'Disable AST analysis (regex-only)')
  .action(async (targetPath: string, opts) => {
    const format = opts.format as AnalyzeOutputFormat;
    if (!VALID_ANALYZE_FORMATS.includes(format)) {
      console.error(
        `Invalid format: ${format}. Use one of: ${VALID_ANALYZE_FORMATS.join(', ')}`,
      );
      process.exit(1);
    }

    if (opts.language && !VALID_LANGUAGES.includes(opts.language as Language)) {
      console.error(
        `Invalid language: ${opts.language}. Use one of: ${VALID_LANGUAGES.join(', ')}`,
      );
      process.exit(1);
    }

    const failGrade = opts.failGrade as BaseGrade;
    if (!VALID_GRADES.includes(failGrade)) {
      console.error(
        `Invalid fail-grade: ${failGrade}. Use one of: ${VALID_GRADES.join(', ')}`,
      );
      process.exit(1);
    }

    const { exitCode, output } = await analyzeCommand(targetPath, {
      format,
      language: opts.language as Language | undefined,
      failGrade,
      ignore: opts.ignore ?? [],
      ignoreFile: opts.ignoreFile,
      maxFiles: parseInt(opts.maxFiles, 10),
      verbose: opts.verbose,
      noMigration: !opts.migration,
      showAll: opts.showAll ?? false,
      noContext: !opts.context,
      noAst: !opts.ast,
    });

    console.log(output);
    process.exit(exitCode);
  });

program.parse();
