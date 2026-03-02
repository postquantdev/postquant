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
