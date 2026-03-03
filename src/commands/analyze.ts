import { stat } from 'node:fs/promises';
import { join, resolve, basename, extname } from 'node:path';
import chalk from 'chalk';
import { discoverFiles } from '../scanner/code/discovery.js';
import { matchFile } from '../scanner/code/matcher.js';
import { classifyCodeFindings } from '../scanner/code/classifier.js';
import { gradeCodeScan, shouldFailForCodeGrade } from '../scanner/code/grader.js';
import { formatCodeTerminal } from '../output/terminal-code.js';
import { formatCodeJson } from '../output/json-code.js';
import { formatSarif } from '../output/sarif.js';
import { formatCbom } from '../output/cbom.js';
import type { AnalyzeOptions, CodeFinding, Language, Grade } from '../types/index.js';

/** Extension → Language mapping (duplicated from discovery for single-file mode). */
const EXTENSION_MAP: Record<string, Language> = {
  '.py': 'python',
  '.pyw': 'python',
  '.pyi': 'python',
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'javascript',
  '.mts': 'javascript',
  '.cts': 'javascript',
  '.tsx': 'javascript',
  '.go': 'go',
  '.java': 'java',
};

interface AnalyzeResult {
  exitCode: number;
  output: string;
  grade: Grade | null;
}

export async function analyzeCommand(
  targetPath: string,
  options: AnalyzeOptions,
): Promise<AnalyzeResult> {
  const absPath = resolve(targetPath);

  let fileStat;
  try {
    fileStat = await stat(absPath);
  } catch {
    return {
      exitCode: 1,
      output: chalk.red(`Error: path does not exist: ${targetPath}`),
      grade: null,
    };
  }

  const startTime = Date.now();
  const allFindings: CodeFinding[] = [];
  let filesScanned = 0;

  if (fileStat.isFile()) {
    // Single file mode
    const ext = extname(absPath);
    const lang = EXTENSION_MAP[ext];
    if (lang && (!options.language || options.language === lang)) {
      const { findings } = await matchFile(absPath, lang);
      // Normalize file paths to be relative-ish (just the basename for single files)
      for (const f of findings) {
        f.file = basename(absPath);
      }
      allFindings.push(...findings);
      filesScanned = 1;
    } else {
      filesScanned = 1;
    }
  } else {
    // Directory mode
    const discovered = await discoverFiles(absPath, {
      ignore: options.ignore,
      ignoreFile: options.ignoreFile,
      maxFiles: options.maxFiles,
      language: options.language,
    });

    filesScanned = discovered.length;

    for (const file of discovered) {
      const fullPath = join(absPath, file.path);
      try {
        const { findings } = await matchFile(fullPath, file.language);
        // Normalize to relative path from scan root
        for (const f of findings) {
          f.file = file.path;
        }
        allFindings.push(...findings);
      } catch {
        // Skip files that can't be read
      }
    }
  }

  const durationMs = Date.now() - startTime;
  const scanRoot = fileStat.isFile() ? absPath : absPath;

  // Pipeline: classify → grade → format
  const classified = classifyCodeFindings(allFindings, scanRoot, filesScanned, durationMs);
  const graded = gradeCodeScan(classified);

  // Format output
  let output: string;
  switch (options.format) {
    case 'json':
      output = formatCodeJson(graded);
      break;
    case 'sarif':
      output = formatSarif(graded);
      break;
    case 'cbom':
      output = formatCbom(graded);
      break;
    case 'terminal':
    default:
      output = formatCodeTerminal(graded, {
        verbose: options.verbose,
        noMigration: options.noMigration,
      });
      break;
  }

  // Determine exit code
  const shouldFail = shouldFailForCodeGrade(graded.baseGrade, options.failGrade);
  const exitCode = shouldFail ? 1 : 0;

  return {
    exitCode,
    output,
    grade: graded.grade,
  };
}
