"""
LLM-Based Intent Audit Module.

Uses LLMs to reason about semantic alignment between declared purpose and implementation.
"""

import json
import time
import re
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum

from loguru import logger

from skillguard.config import Settings, get_settings
from skillguard.core.skill import Skill
from skillguard.taxonomy import ThreatCategory, ThreatSeverity, ThreatIndicator


class ViolationType(str, Enum):
    SEMANTIC_MISMATCH = "semantic_mismatch"
    HIDDEN_CAPABILITY = "hidden_capability"
    DATA_EXFILTRATION = "data_exfiltration"
    CODE_EXECUTION = "code_execution"
    OBFUSCATION = "obfuscation"
    NONE = "none"


@dataclass
class LLMViolation:
    type: ViolationType
    description: str
    severity: str
    line_numbers: List[int] = field(default_factory=list)
    code_snippet: str = ""
    confidence: float = 0.8


@dataclass  
class LLMAuditResult:
    score: float
    has_violations: bool = False
    violations: List[LLMViolation] = field(default_factory=list)
    indicators: List[ThreatIndicator] = field(default_factory=list)
    consensus: bool = True
    total_tokens: int = 0
    latency_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "has_violations": self.has_violations,
            "violations": [{"type": v.type.value, "description": v.description} for v in self.violations],
            "indicators": [ind.to_dict() for ind in self.indicators],
        }


SYSTEM_PROMPT = """You are a security auditor analyzing AI tool definitions for threats.
Respond with JSON: {"has_violations": bool, "overall_risk": "none|low|medium|high|critical",
"violations": [{"type": "semantic_mismatch|hidden_capability|data_exfiltration|code_execution|obfuscation",
"description": "...", "severity": "low|medium|high|critical", "line_numbers": [], "code_snippet": ""}]}"""


class LLMAuditor:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._openai = None
        self._anthropic = None
    
    def _get_openai(self):
        if not self._openai:
            try:
                from openai import OpenAI
                key = self.settings.llm.openai_api_key
                if key and key.get_secret_value():
                    self._openai = OpenAI(api_key=key.get_secret_value())
            except: pass
        return self._openai
    
    def _get_anthropic(self):
        if not self._anthropic:
            try:
                from anthropic import Anthropic
                key = self.settings.llm.anthropic_api_key
                if key and key.get_secret_value():
                    self._anthropic = Anthropic(api_key=key.get_secret_value())
            except: pass
        return self._anthropic
    
    def audit(self, skill: Skill, provider: str = "openai") -> LLMAuditResult:
        start = time.time()
        result = LLMAuditResult(score=0.0)
        
        prompt = f"""Analyze this skill:
Name: {skill.manifest.name}
Description: {skill.manifest.description}
Code ({skill.code.filename}):
```{skill.code.language.value}
{skill.code.content[:6000]}
```"""
        
        parsed = self._query_llm(provider, prompt)
        if parsed:
            result.has_violations = parsed.get("has_violations", False)
            for v in parsed.get("violations", []):
                try:
                    result.violations.append(LLMViolation(
                        type=ViolationType(v.get("type", "none")),
                        description=v.get("description", ""),
                        severity=v.get("severity", "medium"),
                        line_numbers=v.get("line_numbers", []),
                    ))
                except: pass
            result.indicators = self._to_indicators(result.violations)
            result.score = self._calc_score(parsed, result.violations)
        
        result.latency_ms = (time.time() - start) * 1000
        return result
    
    def _query_llm(self, provider: str, prompt: str) -> Optional[Dict]:
        try:
            if provider == "openai" and self._get_openai():
                resp = self._openai.chat.completions.create(
                    model=self.settings.llm.openai_model,
                    messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
                    temperature=0, response_format={"type": "json_object"})
                return json.loads(resp.choices[0].message.content)
            elif provider == "anthropic" and self._get_anthropic():
                resp = self._anthropic.messages.create(
                    model=self.settings.llm.anthropic_model, max_tokens=2048,
                    system=SYSTEM_PROMPT, messages=[{"role": "user", "content": prompt}])
                match = re.search(r'\{[\s\S]*\}', resp.content[0].text)
                return json.loads(match.group()) if match else None
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
        return None
    
    def _to_indicators(self, violations: List[LLMViolation]) -> List[ThreatIndicator]:
        mapping = {
            ViolationType.SEMANTIC_MISMATCH: ThreatCategory.SEMANTIC_MISMATCH,
            ViolationType.DATA_EXFILTRATION: ThreatCategory.DATA_EXFILTRATION,
            ViolationType.CODE_EXECUTION: ThreatCategory.ARBITRARY_CODE_EXECUTION,
        }
        return [ThreatIndicator(
            name=f"LLM: {v.type.value}", description=v.description,
            category=mapping.get(v.type, ThreatCategory.UNKNOWN),
            severity={"critical": ThreatSeverity.CRITICAL, "high": ThreatSeverity.HIGH,
                     "medium": ThreatSeverity.MEDIUM}.get(v.severity, ThreatSeverity.MEDIUM),
            confidence=v.confidence, line_numbers=v.line_numbers
        ) for v in violations]
    
    def _calc_score(self, parsed: Dict, violations: List) -> float:
        if not parsed.get("has_violations"): return 0.0
        base = {"none": 0, "low": 20, "medium": 50, "high": 75, "critical": 95}.get(parsed.get("overall_risk", "medium"), 50)
        return min(100, base + len(violations) * 10)
