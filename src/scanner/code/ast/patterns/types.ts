import type { Language, CryptoCategory, RiskLevel } from '../../../../types/index.js';

export interface ImportConstraint {
  module: string;
  symbol?: string;
  allowAlias: boolean;
}

export interface ASTPattern {
  id: string;
  language: Language;
  category: CryptoCategory;
  algorithm: string;
  risk: RiskLevel;
  query: string;
  /** If set, the analyzer checks that @obj resolves to one of these imports */
  requiredImports?: ImportConstraint[];
  /** Method names to match against @method capture (case-sensitive) */
  methodNames?: string[];
  description: string;
  migration: string;
}
