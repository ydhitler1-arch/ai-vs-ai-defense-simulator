# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
No versioned releases have been made yet, so everything is listed under
Unreleased.

## [Unreleased]

### Added
- Initial release of the AI vs AI Cyber Defense Simulator: Q-learning attacker
  and defender agents, Snort IDS and traffic-rate monitoring, `iptables`-based
  firewall responses, metrics logging and plot generation, with the lab split
  across `att/`, `def/`, `mon/` and `tar/`.
- `main.py` command-line interface with `simulate`, `visualize`, `test` and
  `reset` modes, plus `--episodes`, `--steps`, `--resume`, `--no-plots` and
  `--strict` options.
- README with lab layout, how the simulation works, requirements and usage.
- MIT `LICENSE`.
- `.gitattributes` to normalize line endings and mark binary files.
- Community files: `CONTRIBUTING.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md`.
- GitHub issue templates (bug report, feature request) and a pull request
  template.
