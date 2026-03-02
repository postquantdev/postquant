import { readFileSync } from 'node:fs';
import chalk from 'chalk';
import { scanHost } from '../scanner/tls.js';
import { classify } from '../scanner/classifier.js';
import { grade, shouldFailForGrade } from '../scanner/grader.js';
import { formatTerminal } from '../output/terminal.js';
import { formatJson } from '../output/json.js';
import type { GradedResult, ScanOptions, Grade } from '../types/index.js';

interface ParsedHost {
  host: string;
  port: number;
}

function parseHost(input: string): ParsedHost {
  const lastColon = input.lastIndexOf(':');
  if (lastColon === -1) {
    return { host: input, port: 443 };
  }

  const portStr = input.slice(lastColon + 1);
  const port = parseInt(portStr, 10);

  if (isNaN(port) || port <= 0 || port > 65535) {
    return { host: input, port: 443 };
  }

  return { host: input.slice(0, lastColon), port };
}

function readHostsFile(filePath: string): string[] {
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
    const { host, port } = parseHost(input);

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

const GRADE_ORDER: Grade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

function getWorstGrade(results: GradedResult[]): Grade | null {
  if (results.length === 0) return null;
  let worst = 0;
  for (const r of results) {
    const idx = GRADE_ORDER.indexOf(r.grade);
    if (idx > worst) worst = idx;
  }
  return GRADE_ORDER[worst];
}
