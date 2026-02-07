"""
Tests for the hybrid scoring module.
"""

import pytest
from skillguard.core.skill import Skill
from skillguard.detection.hybrid import HybridScorer
from skillguard.taxonomy import LabelCategory


class TestHybridScorer:
    """Tests for hybrid scoring."""
    
    def test_low_scores_benign(self):
        skill = Skill.from_components("# Test", "code")
        scorer = HybridScorer()
        
        result = scorer.calculate(sifa_score=10, llm_score=5, skill=skill)
        
        assert result.risk_level == "BENIGN"
        assert result.label == LabelCategory.BENIGN
        assert result.final_score < 20
    
    def test_high_scores_malicious(self):
        skill = Skill.from_components("# Test", "code")
        scorer = HybridScorer()
        
        result = scorer.calculate(sifa_score=90, llm_score=85, skill=skill)
        
        assert result.risk_level == "MALICIOUS"
        assert result.label == LabelCategory.MALICIOUS
        assert result.final_score > 80
    
    def test_popularity_penalty(self):
        skill = Skill.from_components("# Test", "code")
        skill.metadata.github_stars = 1000  # Popular = lower penalty
        
        scorer = HybridScorer()
        result1 = scorer.calculate(50, 50, skill)
        
        skill.metadata.github_stars = 0  # Unpopular = higher penalty
        result2 = scorer.calculate(50, 50, skill)
        
        # Unpopular should have higher final score (more risky)
        assert result2.final_score >= result1.final_score
