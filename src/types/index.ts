export type RiskLevel = 'critical' | 'moderate' | 'safe';

export type Grade = 'A+' | 'A' | 'A-' | 'B+' | 'B' | 'B-' | 'C+' | 'C' | 'C-' | 'D+' | 'D' | 'D-' | 'F';

export type BaseGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export type GradeModifier = '+' | '' | '-';

export type ComponentType =
  | 'protocol'
  | 'certificate'
  | 'keyExchange'
  | 'cipher'
  | 'hash';

export type OutputFormat = 'terminal' | 'json';

export interface TlsScanResult {
  host: string;
  port: number;
  protocol: string | null;
  cipher: {
    name: string;
    standardName: string;
    version: string;
    bits: number;
  } | null;
  certificate: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    serialNumber: string;
    fingerprint256: string;
    sigAlgorithm: string;
    publicKeyAlgorithm: string;
    publicKeySize: number;
    curve?: string;
  } | null;
  ephemeralKeyInfo: {
    type: string;
    name?: string;
    size: number;
  } | null;
}

export interface ClassifiedFinding {
  component: ComponentType;
  algorithm: string;
  keySize?: number;
  curve?: string;
  risk: RiskLevel;
  reason: string;
  migration?: string;
}

export interface ClassifiedResult {
  host: string;
  port: number;
  findings: ClassifiedFinding[];
}

export interface GradedResult {
  host: string;
  port: number;
  grade: Grade;
  baseGrade: BaseGrade;
  modifier: GradeModifier;
  pqcDetected: boolean;
  findings: ClassifiedFinding[];
  migrationNotes: string[];
  summary: {
    critical: number;
    moderate: number;
    safe: number;
    total: number;
  };
}

export interface ScanReport {
  version: string;
  timestamp: string;
  results: GradedResult[];
}

export interface ScanOptions {
  format: OutputFormat;
  timeout: number;
  verbose: boolean;
  failGrade: BaseGrade;
  file?: string;
}

// === Code Scanner Types ===

export type Language = 'python' | 'javascript' | 'go' | 'java' | 'c' | 'rust';

export type CryptoCategory =
  | 'asymmetric-encryption'
  | 'digital-signature'
  | 'key-exchange'
  | 'weak-symmetric'
  | 'weak-hash'
  | 'broken-cipher'
  | 'safe-symmetric'
  | 'safe-hash'
  | 'pqc-algorithm';

export type AnalyzeOutputFormat = 'terminal' | 'json' | 'sarif' | 'cbom';

export interface DiscoveredFile {
  /** File path relative to scan root */
  path: string;
  /** Detected language */
  language: Language;
}

export interface CryptoPattern {
  /** Unique ID, e.g., 'python-rsa-keygen' */
  id: string;
  language: Language;
  category: CryptoCategory;
  /** Algorithm name, e.g., 'RSA-2048', 'ECDSA', 'AES-128' */
  algorithm: string;
  risk: RiskLevel;
  confidence: 'verified' | 'high' | 'medium' | 'low';

  /** Import/require/use statement patterns */
  importPatterns?: RegExp[];
  /** Function call / instantiation patterns (at least one required) */
  callPatterns: RegExp[];
  /** Nearby lines that increase confidence */
  contextPatterns?: RegExp[];

  /** Extract key size from matched line */
  keySizeExtractor?: RegExp;
  /** Evaluate key size to determine risk */
  keySizeRisk?: (size: number) => RiskLevel;

  description: string;
  migration: string;
  nistRef?: string;
  cweId?: string;
}

export interface CodeFinding {
  /** Pattern ID that matched */
  patternId: string;
  /** Source file path (relative to scan root) */
  file: string;
  /** Line number (1-indexed) */
  line: number;
  /** The matched line content (trimmed) */
  matchedLine: string;
  /** Detected language */
  language: Language;
  /** Crypto category */
  category: CryptoCategory;
  /** Algorithm name, e.g., 'RSA-2048', 'ECDSA-P256', 'AES-128' */
  algorithm: string;
  /** Key size if detected */
  keySize?: number;
  /** Elliptic curve name if detected */
  curve?: string;
  /** Risk level */
  risk: RiskLevel;
  /** Human-readable reason */
  reason: string;
  /** Migration recommendation */
  migration?: string;
  /** Match confidence */
  confidence: 'verified' | 'high' | 'medium' | 'low';
  /** AST scope information, if available */
  scopeInfo?: ScopeInfo;
  /** Whether this finding was enriched/produced by AST analysis */
  astEnriched?: boolean;
}

export interface ScopeInfo {
  /** Enclosing function name, if any */
  functionName?: string;
  /** Enclosing class name, if any */
  className?: string;
  /** Is this inside a test function/class? Structural detection */
  isTestCode: boolean;
  /** Is this inside a conditional/fallback block? */
  isConditionalPath: boolean;
}

export interface CodeScanResult {
  /** Root directory that was scanned */
  scanRoot: string;
  /** All findings */
  findings: CodeFinding[];
  /** Files scanned count */
  filesScanned: number;
  /** Files with findings count */
  filesWithFindings: number;
  /** Languages detected */
  languagesDetected: Language[];
  /** Scan duration in milliseconds */
  durationMs: number;
}

export interface FileBreakdown {
  file: string;
  language: Language;
  findings: CodeFinding[];
  criticalCount: number;
  moderateCount: number;
  safeCount: number;
}

export interface CodeGradedResult {
  /** Root directory */
  scanRoot: string;
  /** Overall display grade (e.g., 'C+', 'B-') */
  grade: Grade;
  /** Base grade without modifier */
  baseGrade: BaseGrade;
  /** Grade modifier */
  modifier: GradeModifier;
  /** Whether any PQC algorithms were detected */
  pqcDetected: boolean;
  /** All findings */
  findings: CodeFinding[];
  /** Migration notes (unique) */
  migrationNotes: string[];
  /** Summary counts */
  summary: {
    critical: number;
    moderate: number;
    safe: number;
    total: number;
    filesScanned: number;
    filesWithFindings: number;
  };
  /** Per-file breakdown */
  fileBreakdown: FileBreakdown[];
}

export interface AnalyzeOptions {
  format: AnalyzeOutputFormat;
  language?: Language;
  failGrade: BaseGrade;
  ignore: string[];
  ignoreFile: string;
  maxFiles: number;
  verbose: boolean;
  noMigration: boolean;
  showAll?: boolean;
  noContext?: boolean;
  noAst?: boolean;
}

// ── Risk Assessment Types (v0.3.0) ──────────────────────────────

export type UsageContext =
  | 'authentication'
  | 'encryption'
  | 'key-exchange'
  | 'digital-signature'
  | 'integrity-check'
  | 'protocol-compliance'
  | 'legacy-support'
  | 'test-fixture'
  | 'documentation'
  | 'unknown';

export type AdjustedRisk = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface ContextSignal {
  type: 'file-path' | 'function-name' | 'variable-name' | 'nearby-code' | 'import-context' | 'api-pattern' | 'ast-scope';
  value: string;
  influence: 'increases-risk' | 'decreases-risk' | 'neutral';
}

export interface RiskContext {
  usageContext: UsageContext;
  adjustedRisk: AdjustedRisk;
  contextEvidence: string[];
  signals: ContextSignal[];
}

export interface AssessedFinding extends CodeFinding {
  originalRisk: RiskLevel;
  riskContext: RiskContext;
}

/** Type guard: does this finding carry risk-assessment context? */
export function isAssessedFinding(f: CodeFinding): f is AssessedFinding {
  return 'riskContext' in f;
}
