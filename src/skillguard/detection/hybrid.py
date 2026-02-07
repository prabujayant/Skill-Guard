"""
Hybrid Scoring Module - Combines SIFA and LLM scores with popularity metrics.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional
from skillguard.config import Settings, get_settings
from skillguard.core.skill import Skill
from skillguard.taxonomy import LabelCategory, ThreatSeverity


@dataclass
class HybridScore:
    final_score: float
    sifa_score: float
    llm_score: float
    popularity_penalty: float
    risk_level: str
    label: LabelCategory
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_score": self.final_score,
            "sifa_score": self.sifa_score,
            "llm_score": self.llm_score,
            "popularity_penalty": self.popularity_penalty,
            "risk_level": self.risk_level,
            "label": self.label.value,
        }


class HybridScorer:
    """
    Combines SIFA + LLM scores using configurable weights.
    
    Formula: Final_Score = (SIFA × 0.4) + (LLM × 0.4) + (Popularity_Penalty × 0.2)
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.sifa_weight = self.settings.hybrid.sifa_weight
        self.llm_weight = self.settings.hybrid.llm_weight
        self.popularity_weight = self.settings.hybrid.popularity_weight
        self.thresholds = self.settings.hybrid.thresholds
    
    def calculate(
        self,
        sifa_score: float,
        llm_score: float,
        skill: Skill,
    ) -> HybridScore:
        """Calculate hybrid score combining all components."""
        # Calculate popularity penalty (lower popularity = higher penalty)
        popularity = skill.metadata.get_popularity_score()
        popularity_penalty = (1 - popularity) * 20
        
        # Weighted combination
        final = (
            sifa_score * self.sifa_weight +
            llm_score * self.llm_weight +
            popularity_penalty * self.popularity_weight
        )
        final = min(100, max(0, final))
        
        # Determine risk level and label
        risk_level = self._get_risk_level(final)
        label = self._get_label(final)
        
        return HybridScore(
            final_score=final,
            sifa_score=sifa_score,
            llm_score=llm_score,
            popularity_penalty=popularity_penalty,
            risk_level=risk_level,
            label=label,
        )
    
    def _get_risk_level(self, score: float) -> str:
        if score <= self.thresholds["benign"]:
            return "BENIGN"
        elif score <= self.thresholds["suspicious"]:
            return "SUSPICIOUS"
        elif score <= self.thresholds["high_risk"]:
            return "HIGH-RISK"
        return "MALICIOUS"
    
    def _get_label(self, score: float) -> LabelCategory:
        if score <= self.thresholds["benign"]:
            return LabelCategory.BENIGN
        elif score <= self.thresholds["high_risk"]:
            return LabelCategory.SUSPICIOUS
        return LabelCategory.MALICIOUS
