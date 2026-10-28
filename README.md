# AI vs AI Cyber Defense Simulator

A reinforcement-learning lab in which an attacker agent and a defender agent
train against each other inside an isolated virtual network. Both agents use
Q-learning; the defender watches IDS alerts and traffic and responds with
firewall actions, learning over many episodes which responses work best.

> **Authorized lab use only.** Run this only on a private, isolated network of
> virtual machines that you own and control.

## Background

This started as a college mini project. The code in this repository is what
was actually run in the lab described below.

## Lab layout

The simulator runs on VirtualBox VMs attached to a VirtualBox internal network
named `cyberlab`, with no route to the internet or the host LAN. Each VM has a
static IP in `192.168.50.0/24`, configured in `config.py`:

| Folder | Role                                      | OS         | IP              |
|--------|-------------------------------------------|------------|-----------------|
| `att/` | Attacker VM                               | Kali Linux | `192.168.50.10` |
| `tar/` | Target VM (Apache, SSH, MySQL, DVWA)      | Ubuntu     | `192.168.50.20` |
| `def/` | Defender VM (simulation, IDS, firewall)   | Ubuntu     | `192.168.50.30` |

Each folder is deployed to its own VM and carries its own copy of `config.py`.

### VirtualBox setup

1. Create one Kali Linux VM (attacker) and two Ubuntu VMs (target, defender).
2. Set each VM's network adapter to **Internal Network** with the name
   `cyberlab`.
3. Assign each VM its static IP from the table above (for example with Netplan
   on Ubuntu, or the network settings on Kali).
4. Copy each folder to its VM and run the simulation from `def/` on the
   defender.

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

## Live mode

Normally the engine simulates the attacker. In live mode it does not: the attacker is a
separate process on the Kali VM, Snort on the target raises real alerts, and the defender
reacts to the alerts whose source is the attacker's IP (alerts from any other host, such as
the defender itself, are ignored). Start the defender first, then the attacker:

```bash
sudo python3 main.py --live --episodes 3 --steps 60      # defender VM, in def/
python3 attacker_ai.py --mode train --episodes 1          # attacker VM, in att/
```

`--live-step SECONDS` sets the time per defender decision (default 1 s). Metrics keep their
names with live meanings: `attack_success_rate` is the share of attack steps in which the
attacker was not contained, and `detection_accuracy` the share in which the defender responded.

### Enforcing blocks on the target

By default the defender applies its `iptables` rules on the defender VM, which the attacker's
traffic does not pass through, so blocks do not stop a real attacker. To enforce on the target
instead, the defender runs `iptables` there over SSH. One-time setup:

1. On the **defender**, create a key used only for this (the engine runs as root, so the key
   belongs to root), then print the complete line the target needs:

   ```bash
   sudo ssh-keygen -t ed25519 -N "" -C cyberlab-fw -f /opt/cyberlab/cyberlab_fw_key
   ```

   ```bash
   sudo sh -c 'echo "from=\"192.168.50.30\",restrict $(cat /opt/cyberlab/cyberlab_fw_key.pub)"'
   ```

   Copy that whole printed line (it starts with `from=` and ends with `cyberlab-fw`).

2. On the **target**, create a locked user that may log in only with that key, only from the
   defender, and may run only `iptables` through sudo. Run these one at a time:

   ```bash
   sudo adduser --disabled-password --gecos "" cyberfw
   ```

   ```bash
   sudo install -d -m 700 -o cyberfw -g cyberfw /home/cyberfw/.ssh
   ```

   The next command waits for input: paste the line you copied, press Enter, then Ctrl+D.

   ```bash
   sudo tee /home/cyberfw/.ssh/authorized_keys
   ```

   ```bash
   sudo chown cyberfw:cyberfw /home/cyberfw/.ssh/authorized_keys && sudo chmod 600 /home/cyberfw/.ssh/authorized_keys
   ```

   Check the file holds the real key, with `ssh-ed25519 ...` near the end of the line:

   ```bash
   sudo cat /home/cyberfw/.ssh/authorized_keys
   ```

   Then allow `iptables` only:

   ```bash
   echo 'cyberfw ALL=(root) NOPASSWD: /usr/sbin/iptables' | sudo tee /etc/sudoers.d/cyberfw
   ```

   ```bash
   sudo chmod 440 /etc/sudoers.d/cyberfw && sudo visudo -c
   ```

3. On the **target**, find the interface that carries the lab network (the one holding
   `192.168.50.20`) with `ip -br a`. Rules are limited to that interface so the target's other
   interfaces stay reachable.

4. On the **defender**, check the connection:

   ```bash
   sudo ssh -i /opt/cyberlab/cyberlab_fw_key -o IdentitiesOnly=yes -o UserKnownHostsFile=/opt/cyberlab/cyberlab_fw_known_hosts -o StrictHostKeyChecking=accept-new cyberfw@192.168.50.20 sudo -n iptables -S INPUT
   ```

5. Run the defender with enforcement turned on:

   ```bash
   sudo CYBERLAB_FW_HOST=192.168.50.20 CYBERLAB_FW_IFACE=enp0s8 python3 main.py --live --episodes 3 --steps 60
   ```

   Other settings: `CYBERLAB_FW_USER` (default `cyberfw`), `CYBERLAB_FW_KEY`,
   `CYBERLAB_FW_KNOWN_HOSTS`. If the target cannot be reached the defender stops at start-up
   instead of pretending to enforce.

The rules live in their own chain, `CYBERLAB_DEFENSE`, and the defender is accepted at the top of
`INPUT` outside that chain, so a rule can never cut off the control connection. If you ever need
to undo everything from the target's console:

```bash
sudo iptables -F CYBERLAB_DEFENSE && sudo iptables -D INPUT -i enp0s8 -j CYBERLAB_DEFENSE
```

## Notes

- Trained Q-tables (`*.pkl`), `*.restore` files and `__pycache__` are
  git-ignored, so train your own models after cloning.
- `config.py` contains the DVWA default credentials (`admin` / `password`).
  These are the publicly known defaults for the intentionally vulnerable DVWA
  app and must never be used on a real system.

## License

MIT, see [LICENSE](LICENSE).
