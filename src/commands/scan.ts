import { readFileSync } from 'node:fs';
import chalk from 'chalk';
import { scanHost } from '../scanner/tls.js';
import { classify } from '../scanner/classifier.js';
import { grade, shouldFailForGrade } from '../scanner/grader.js';
import { formatTerminal } from '../output/terminal.js';
import { formatJson } from '../output/json.js';
import { validateHostname, validatePort, validateFilePath } from '../utils/validate.js';
import type { GradedResult, ScanOptions, BaseGrade } from '../types/index.js';

interface ParsedHost {
  host: string;
  port: number;
}

function parseHost(input: string): ParsedHost | null {
  const lastColon = input.lastIndexOf(':');
  if (lastColon === -1) {
    if (!validateHostname(input)) return null;
    return { host: input, port: 443 };
  }

  const portStr = input.slice(lastColon + 1);
  const port = parseInt(portStr, 10);

  // If what follows the last colon doesn't look like a port number at all,
  // treat the whole input as a hostname (e.g. IPv6 without brackets)
  if (isNaN(port) || portStr.length === 0) {
    if (!validateHostname(input)) return null;
    return { host: input, port: 443 };
  }

  // Port was parsed as a number — validate it strictly
  if (!validatePort(port)) return null;

  const host = input.slice(0, lastColon);
  if (!validateHostname(host)) return null;

  return { host, port };
}

function readHostsFile(filePath: string): string[] {
  if (!validateFilePath(filePath)) {
    throw new Error(`Invalid file path: contains prohibited characters`);
  }
  const content = readFileSync(filePath, 'utf-8');
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

export async function scanCommand(
  hosts: string[],
  options: ScanOptions,
): Promise<number> {
  const allHostInputs = [...hosts];
  if (options.file) {
    try {
      const fileHosts = readHostsFile(options.file);
      allHostInputs.push(...fileHosts);
    } catch (err) {
      console.error(
        chalk.red(`Error reading hosts file: ${(err as Error).message}`),
      );
      return 1;
    }
  }

  if (allHostInputs.length === 0) {
    console.error(chalk.red('No hosts specified. Use: postquant scan <host> or --file <path>'));
    return 1;
  }

  const results: GradedResult[] = [];
  let hadErrors = false;

  for (const input of allHostInputs) {
    const parsed = parseHost(input);

    if (!parsed) {
      hadErrors = true;
      console.error(
        chalk.red(`\nInvalid host: ${input} — contains prohibited characters or invalid port`),
      );
      continue;
    }

    const { host, port } = parsed;

    try {
      const scanResult = await scanHost(host, port, options.timeout);
      const classified = classify(scanResult);
      const graded = grade(classified);
      results.push(graded);
    } catch (err) {
      hadErrors = true;
      console.error(
        chalk.red(`\nError scanning ${host}:${port}: ${(err as Error).message}`),
      );
    }
  }

  if (results.length > 0) {
    if (options.format === 'json') {
      console.log(formatJson(results));
    } else {
      for (const result of results) {
        console.log(formatTerminal(result));
      }
    }
  }

  if (hadErrors) return 1;

  const worstGrade = getWorstGrade(results);
  if (worstGrade && shouldFailForGrade(worstGrade, options.failGrade)) {
    return 1;
  }

  return 0;
}

const GRADE_ORDER: BaseGrade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

function getWorstGrade(results: GradedResult[]): BaseGrade | null {
  if (results.length === 0) return null;
  let worst = 0;
  for (const r of results) {
    const idx = GRADE_ORDER.indexOf(r.baseGrade);
    if (idx > worst) worst = idx;
  }
  return GRADE_ORDER[worst];
}
