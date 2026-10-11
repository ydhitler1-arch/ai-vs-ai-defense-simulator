# AI vs AI Cyber Defense Simulator

A reinforcement-learning lab in which an attacker agent and a defender agent
train against each other inside an isolated virtual network. Both agents use
Q-learning; the defender watches IDS alerts and traffic and responds with
firewall actions, learning over many episodes which responses work best.

> **Authorized lab use only.** Run this only on a private, isolated network of
> virtual machines that you own and control.

## Lab layout

The simulator assumes four VMs on an internal `192.168.50.0/24` network
(`cyberlab`), configured in `config.py`:

| Folder | Role                         | IP              |
|--------|------------------------------|-----------------|
| `att/` | Attacker VM                  | `192.168.50.10` |
| `tar/` | Target VM (Apache, SSH, MySQL, DVWA) | `192.168.50.20` |
| `def/` | Defender VM (simulation engine, firewall) | `192.168.50.30` |
| `mon/` | Monitor VM (Snort IDS, metrics) | `192.168.50.40` |

Each folder is deployed to its own VM and carries its own copy of `config.py`.

## How it works

**Attacker actions:** `IDLE`, `SCAN`, `SQL_INJECTION`, `BRUTE_FORCE`, `DDOS`

**Defender actions:** `LOG_ONLY`, `RATE_LIMIT`, `BLOCK_IP`, `ISOLATE_TARGET`

Each episode is a series of steps. On every step the attacker picks an attack,
the IDS (Snort alerts plus a traffic-rate monitor) reports what it saw, and the
defender picks a response that is applied through `iptables`. Both agents are
rewarded or penalised (for example, a successful block, a false positive or a
missed attack for the defender) and update their Q-tables, with an
epsilon-greedy policy that decays over time. Reward values and learning
parameters are all in `config.py`.

## Components (`def/`)

| File                   | Purpose                                         |
|------------------------|-------------------------------------------------|
| `main.py`              | Entry point and CLI                             |
| `simulation_engine.py` | Runs episodes and coordinates the agents        |
| `attacker_ai.py`       | Attacker Q-learning agent                       |
| `defender_ai.py`       | Defender Q-learning agent                       |
| `ids_monitor.py`       | Parses Snort fast alerts and monitors traffic rate |
| `firewall_manager.py`  | Applies defender actions via an `iptables` chain |
| `metrics_logger.py`    | Records per-episode metrics                     |
| `visualizer.py`        | Generates plots from the metrics                |
| `utils.py`             | Shared helpers                                  |

## Requirements

- Python 3 on each VM
- `numpy`, `pandas`, `matplotlib`, `seaborn`
- Snort and `iptables` on the relevant VMs, and Apache/MySQL/SSH plus
  [DVWA](https://github.com/digininja/DVWA) on the target
- Root privileges on the defender for firewall changes

```bash
pip install numpy pandas matplotlib seaborn
```

## Usage

Run from the `def/` directory on the defender VM:

```bash
python3 main.py                     # full simulation
python3 main.py --episodes 50       # override episode count
python3 main.py --steps 100         # override steps per episode
python3 main.py --resume            # load saved Q-tables and keep training
python3 main.py --mode test         # 1-episode smoke test
python3 main.py --mode visualize    # generate plots from existing metrics
python3 main.py --mode reset        # delete saved models and metrics, then simulate
```

Other flags: `--no-plots` skips plot generation at the end, and `--strict`
treats validation warnings as errors.

Logs, metrics and graphs are written under `/var/log/cyber-sim/` by default
(see `config.py`).

## Notes

- Trained Q-tables (`*.pkl`), `*.restore` files and `__pycache__` are
  git-ignored, so train your own models after cloning.
- `config.py` contains the DVWA default credentials (`admin` / `password`).
  These are the publicly known defaults for the intentionally vulnerable DVWA
  app and must never be used on a real system.
