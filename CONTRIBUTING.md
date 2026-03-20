# Contributing to Abilities MCP Adapter

We welcome contributions — bug reports, feature ideas, code, documentation, and questions.

## How We Work

This project is built by a human founder and a team of AI agents. The founder does not read or write code. The AI team (Claude, operating across multiple specialized roles) handles architecture, development, code review, testing, and documentation. The founder directs strategy, makes product decisions, and approves what ships.

Every contribution — issue, PR, or discussion — is reviewed by the AI team and discussed with the founder before merging. This means:

- **Response times vary.** We review in batches, not in real-time.
- **PRs require approval.** The `main` branch is protected. All external contributions come through pull requests.
- **We may ask clarifying questions.** Context helps us make better decisions.
- **We may adapt your contribution.** If the direction is right but the implementation needs adjustment for our architecture, we'll work with you on it.

## Reporting Bugs

Open an issue with:
1. What you expected to happen
2. What actually happened
3. Steps to reproduce
4. Your environment (WordPress version, PHP version, MCP client, bridge version)

If the bug involves a specific ability execution, include the ability name, parameters, and the error response.

## Suggesting Features

Open an issue describing:
1. What you want to do (the use case, not just the feature)
2. Why existing tools don't cover it
3. Any ideas on implementation (optional)

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `composer test` if you modified PHP code
4. Write clear commit messages describing what and why
5. Open a PR against `main`
6. Describe what your PR does and which issue it addresses (if any)

### What makes a good PR

- **Focused.** One concern per PR.
- **Tested.** Describe how you verified it works. Run the PHPUnit suite if applicable.
- **PHP lint clean.** `php -l` on all modified files.
- **Documented.** If your change affects user-facing behavior, update the relevant docs.

### What we look for in review

- Does it fit the MCP protocol spec?
- Does it handle WP_Error correctly?
- Does it follow the existing namespace and class patterns?
- Does it maintain backward compatibility with existing MCP clients?

## Code Style

- **PHP 8.0+** with strict types where applicable
- PSR-4 autoloading under `WickedEvolutions\McpAdapter`
- WordPress coding standards for hook names and option keys
- Consistent with existing code patterns

## Security

If you discover a security vulnerability, **do not open a public issue.** Email the details to the contact in SECURITY.md.

## License

By contributing, you agree that your contributions will be licensed under the GPL-2.0-or-later license.
