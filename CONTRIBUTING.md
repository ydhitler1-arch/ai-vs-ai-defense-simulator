# Contributing

Thanks for your interest in the AI vs AI Cyber Defense Simulator!

## Ground rules

- This project is for **authorized, isolated lab use only**. Contributions must
  not add features aimed at attacking real systems or evading detection outside
  the lab network.
- Never commit real credentials, API keys or captured traffic. The DVWA defaults
  in `config.py` are the only credentials that belong in the repo.
- Be respectful and constructive in issues and pull requests.

## Reporting bugs and suggesting features

Open an issue and include:

- What you expected to happen and what actually happened
- The command you ran (e.g. `python3 main.py --mode test`) and any traceback
- Your Python version and OS, and whether you ran in the full VM lab

## Development setup

1. Fork and clone the repo.
2. Install the dependencies:

   ```bash
   pip install numpy pandas matplotlib seaborn
   ```

3. Run the smoke test from `def/` to check your changes:

   ```bash
   python3 main.py --mode test
   ```

   The full lab (Snort, `iptables`, DVWA) is only needed for end-to-end runs.

## Making changes

- Create a branch from `master` (`git checkout -b my-change`).
- Keep each pull request focused on one change.
- Follow the existing style: type hints, docstrings on classes and functions,
  and settings in `config.py` rather than hard-coded values.
- Each VM folder (`att/`, `def/`, `mon/`, `tar/`) has its own copy of
  `config.py`. If you change a shared setting, update every copy.
- Don't commit generated files. Models (`*.pkl`), `*.restore` files and
  `__pycache__` are git-ignored.
- Update the README if you change commands, flags or behaviour.

## Pull requests

1. Make sure the smoke test passes.
2. Push your branch and open a pull request against `master`.
3. Describe what changed and why, and how you tested it.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
