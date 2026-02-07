"""
AgentShepherd Integration.

Provides runtime tool call filtering by integrating with AgentShepherd gateway.
"""

import subprocess
import json
import yaml
from pathlib import Path
from typing import Dict, Optional, List
from loguru import logger

from skillguard.core.skill import Skill
from skillguard.models.base import PredictionResult


class RuntimeDefender:
    """
    Integrate AgentShepherd for runtime protection.
    
    Workflow:
    1. SkillGuard analyzes skill → generates risk score
    2. If high risk → create AgentShepherd rule to block at runtime
    3. AgentShepherd intercepts tool calls and applies rules
    """
    
    def __init__(
        self,
        port: int = 9090,
        config_dir: Path = Path.home() / ".agentshepherd",
        auto_start: bool = True
    ):
        self.port = port
        self.config_dir = Path(config_dir)
        self.rules_dir = self.config_dir / "rules" / "skillguard"
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        if auto_start:
            self.start_shepherd()
    
    def start_shepherd(self) -> bool:
        """Start AgentShepherd daemon if not running."""
        if self.is_running():
            logger.info("AgentShepherd already running")
            return True
        
        try:
            subprocess.run(
                ["agentshepherd", "start"],
                capture_output=True,
                check=True,
                timeout=10
            )
            logger.info(f"✓ AgentShepherd started on port {self.port}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error(f"Failed to start AgentShepherd: {e}")
            logger.warning("Install with: curl -fsSL https://raw.githubusercontent.com/AgentShepherd/agentshepherd/main/install.sh | bash")
            return False
    
    def is_running(self) -> bool:
        """Check if AgentShepherd is running."""
        try:
            result = subprocess.run(
                ["agentshepherd", "status"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def stop_shepherd(self):
        """Stop AgentShepherd daemon."""
        subprocess.run(["agentshepherd", "stop"], capture_output=True)
        logger.info("AgentShepherd stopped")
    
    def add_skillguard_rule(
        self,
        skill: Skill,
        prediction: PredictionResult,
        risk_threshold: float = 0.8
    ) -> Optional[str]:
        """
        Convert SkillGuard ML prediction to AgentShepherd rule.
        
        Args:
            skill: Analyzed skill
            prediction: SkillGuard prediction result
            risk_threshold: Risk score above which to block (0-1)
            
        Returns:
            Rule name if created, None otherwise
        """
        risk_score = prediction.probabilities[0][1]  # Malicious probability
        
        if risk_score < risk_threshold:
            logger.debug(f"Skill {skill.name} below risk threshold ({risk_score:.2f} < {risk_threshold})")
            return None
        
        # Identify threat categories
        threats = self._identify_threats(skill)
        
        # Create blocking rule
        rule = {
            "rules": [
                {
                    "name": f"block-{skill.name}",
                    "match": {
                        "tool_name": skill.name,
                    },
                    "action": "block",
                    "message": (
                        f"🛡️ Blocked by SkillGuard (risk={risk_score:.1%})\\n"
                        f"Threats: {', '.join(threats)}\\n"
                        f"Confidence: {prediction.confidence[0]:.1%}"
                    ),
                    "metadata": {
                        "source": "skillguard",
                        "risk_score": float(risk_score),
                        "threats": threats,
                        "timestamp": str(Path.ctime(Path.cwd()))
                    }
                }
            ]
        }
        
        # Save rule file
        rule_file = self.rules_dir / f"{skill.name}.yaml"
        rule_file.write_text(yaml.dump(rule, default_flow_style=False))
        
        logger.info(f"✓ Created blocking rule for {skill.name} (risk={risk_score:.1%})")
        
        # Hot reload
        self.reload_rules()
        
        return rule["rules"][0]["name"]
    
    def add_pattern_rules(
        self,
        patterns: List[Dict[str, str]],
        rule_file_name: str = "skillguard-patterns"
    ):
        """
        Add pattern-based rules for known attack patterns.
        
        Example:
            patterns = [
                {"block": "**/.env", "message": "Credential theft attempt"},
                {"block": "**/.ssh/id_*", "except": "**/*.pub"},
            ]
        """
        rule = {"rules": []}
        
        for i, pattern in enumerate(patterns):
            rule["rules"].append({
                "name": f"{rule_file_name}-{i}",
                "block": pattern.get("block"),
                "except": pattern.get("except"),
                "message": pattern.get("message", "Blocked by SkillGuard pattern matching"),
                "metadata": {"source": "skillguard-patterns"}
            })
        
        rule_file = self.rules_dir / f"{rule_file_name}.yaml"
        rule_file.write_text(yaml.dump(rule, default_flow_style=False))
        
        logger.info(f"✓ Added {len(patterns)} pattern rules")
        self.reload_rules()
    
    def reload_rules(self):
        """Hot reload AgentShepherd rules."""
        try:
            subprocess.run(
                ["agentshepherd", "reload-rules"],
                capture_output=True,
                check=True,
                timeout=5
            )
            logger.debug("Rules reloaded")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Failed to reload rules: {e}")
    
    def list_rules(self) -> List[Dict]:
        """List all active AgentShepherd rules."""
        try:
            result = subprocess.run(
                ["agentshepherd", "list-rules"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse output (assuming JSON/YAML format)
            rules = yaml.safe_load(result.stdout) if result.stdout else []
            return rules
        except Exception as e:
            logger.error(f"Failed to list rules: {e}")
            return []
    
    def remove_rule(self, rule_name: str):
        """Remove a specific SkillGuard-generated rule."""
        rule_file = self.rules_dir / f"{rule_name}.yaml"
        if rule_file.exists():
            rule_file.unlink()
            self.reload_rules()
            logger.info(f"Removed rule: {rule_name}")
    
    def _identify_threats(self, skill: Skill) -> List[str]:
        """
        Identify specific threat categories from skill analysis.
        
        Maps to threat taxonomy (ACE, exfiltration, reverse shell, etc.)
        """
        from skillguard.taxonomy import ThreatCategory
        
        threats = []
        
        # Check skill metadata for detected threats
        if hasattr(skill, 'analysis_results'):
            results = skill.analysis_results
            
            if results.get('has_subprocess'):
                threats.append("Arbitrary Code Execution")
            if results.get('has_network'):
                threats.append("Data Exfiltration")
            if results.get('has_socket'):
                threats.append("Reverse Shell")
            if results.get('has_file_write') and not results.get('declares_file_write'):
                threats.append("Privilege Escalation")
            if results.get('semantic_mismatch', 0) > 0.3:
                threats.append("Semantic Mismatch")
            if results.get('has_obfuscation'):
                threats.append("Supply Chain Injection")
        
        return threats if threats else ["Unknown Malicious Pattern"]
    
    def deploy_integrated_defense(
        self,
        skills: List[Skill],
        predictions: List[PredictionResult],
        risk_threshold: float = 0.8
    ):
        """
        Deploy integrated defense for a set of analyzed skills.
        
        Workflow:
        1. For each skill, if risk > threshold, create blocking rule
        2. Add pattern-based rules for common attack vectors
        3. Reload all rules
        """
        blocked_count = 0
        
        logger.info(f"Deploying runtime defense for {len(skills)} skills...")
        
        for skill, pred in zip(skills, predictions):
            rule_name = self.add_skillguard_rule(skill, pred, risk_threshold)
            if rule_name:
                blocked_count += 1
        
        # Add common attack patterns
        common_patterns = [
            {"block": "**/.env*", "message": "Credential theft: .env access"},
            {"block": "**/.ssh/id_*", "except": "**/*.pub", "message": "Private key exfiltration"},
            {"block": "**/bash_history", "message": "Shell history exposure"},
            {"block": "**/zsh_history", "message": "Shell history exposure"},
        ]
        self.add_pattern_rules(common_patterns)
        
        logger.info(
            f"✓ Runtime defense deployed: {blocked_count} skills blocked, "
            f"{len(common_patterns)} pattern rules active"
        )


class AgentShepherdProxy:
    """
    Direct API interface to AgentShepherd proxy.
    
    For advanced use cases where you need to intercept/modify requests.
    """
    
    def __init__(self, shepherd_url: str = "http://localhost:9090"):
        self.shepherd_url = shepherd_url
    
    def get_telemetry(self) -> Dict:
        """Retrieve telemetry data from AgentShepherd."""
        import requests
        
        try:
            response = requests.get(f"{self.shepherd_url}/telemetry", timeout=5)
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get telemetry: {e}")
            return {}
    
    def get_blocked_calls(self) -> List[Dict]:
        """Get history of blocked tool calls."""
        telemetry = self.get_telemetry()
        return telemetry.get("blocked_calls", [])
