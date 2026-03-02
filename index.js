#!/usr/bin/env node

const pkg = require('./package.json');

console.log(`
  PostQuant v${pkg.version}
  Post-Quantum Cryptography Auditor

  Scan your code and infrastructure for quantum-vulnerable crypto.

  Status: Early development. Scanner coming soon.
  Website: https://postquant.dev
  GitHub:  https://github.com/postquantdev/postquant

  Run 'postquant --help' for usage (coming soon).
`);
