# Contributing to PostQuant

PostQuant is in early development. Contributions are welcome.

## Setup

```bash
git clone https://github.com/postquantdev/postquant.git
cd postquant
npm install
```

## Development

```bash
npm run build        # Compile TypeScript to dist/
npm test             # Run unit tests (vitest)
npm run test:watch   # Run tests in watch mode
npm run lint         # Type-check without emitting
npm run dev -- scan example.com   # Run from source
```

The project uses TypeScript (strict mode, ESM) with Node's built-in `tls` and `crypto` modules. No heavy frameworks.

## Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Write or update tests
4. Run `npm test` and `npm run lint` before submitting
5. Submit a PR with a clear description of the change

## Code Style

- TypeScript strict mode — no `any` types unless unavoidable
- Async/await over callbacks
- Minimal dependencies
- Tests for new functionality

## Reporting Bugs

Open an issue with the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include steps to reproduce, expected behavior, and your environment (Node version, OS).

## Suggesting Features

Open an issue with the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
