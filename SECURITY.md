# Security Policy

## Scope

This project is a reinforcement-learning simulator that runs attack and defense
agents inside an **isolated lab network**. It is intended for authorized
educational and research use only.

Some behaviour is intentional and is not a vulnerability:

- The target VM runs the deliberately vulnerable [DVWA](https://github.com/digininja/DVWA)
  app, with its public default credentials (`admin` / `password`) in `config.py`.
- The attacker agent performs scans, SQL injection, brute force and DDoS-style
  traffic against the lab target.
- The defender modifies `iptables` rules and needs root.

## Supported versions

Only the latest commit on the `master` branch is supported.

## Reporting a vulnerability

Please report issues privately rather than in a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/ydhitler1-arch/ai-vs-ai-defense-simulator/security/advisories/new)
(Security tab → "Report a vulnerability").

Examples of issues worth reporting:

- Code that could send attack traffic outside the configured lab subnet
  (`192.168.50.0/24`) or to a host other than the configured target
- Command injection or unsafe handling of input in the code that builds shell,
  `iptables` or Snort commands
- Unsafe deserialization: Q-tables are loaded with `pickle`, so loading an
  untrusted `.pkl` file can execute arbitrary code
- Real secrets accidentally committed to the repository

Please include steps to reproduce, the affected file or commit, and the impact.
You can expect an initial response within about a week. This is a personal
project, so fixes are best-effort.

## Safe use

- Run the simulator only on VMs you own, on a host-only or internal network
  with no route to the internet or your real LAN.
- Only load Q-table (`.pkl`) files that you trained yourself.
- Never reuse the DVWA credentials, or expose the DVWA target, outside the lab.
