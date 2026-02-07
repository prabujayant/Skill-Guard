"""
Main SkillAnalyzer - Orchestrates the hybrid detection pipeline.

This module coordinates the SIFA (Static Information Flow Analysis) and 
LLM-based intent auditing to produce comprehensive threat assessments.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
import json

from loguru import logger
from pydantic import BaseModel

from skillguard.config import Settings, get_settings
from skillguard.core.skill import Skill, SkillCorpus
from skillguard.taxonomy import (
    ThreatCategory,
    ThreatSeverity,
    ThreatIndicator,
    ThreatProfile,
    LabelCategory,
    get_severity_score,
)


@dataclass
class AnalysisResult:
    """Complete analysis result for a skill."""
    
    skill_id: str
    skill_name: str
    threat_profile: ThreatProfile
    sifa_findings: Dict[str, Any]
    llm_audit: Dict[str, Any]
    analysis_time_ms: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "skill_id": self.skill_id,
            "skill_name": self.skill_name,
            "threat_profile": self.threat_profile.to_dict(),
            "sifa_findings": self.sifa_findings,
            "llm_audit": self.llm_audit,
            "analysis_time_ms": self.analysis_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class AnalysisConfig(BaseModel):
    """Configuration for analysis run."""
    
    enable_sifa: bool = True
    enable_llm_audit: bool = True
    enable_obfuscation_detection: bool = True
    
    # LLM settings
    llm_provider: str = "openai"  # "openai" or "anthropic" or "both"
    require_consensus: bool = False  # Require both LLMs to agree
    
    # Scoring weights
    sifa_weight: float = 0.4
    llm_weight: float = 0.4
    popularity_weight: float = 0.2
    
    # Thresholds
    risk_threshold_suspicious: int = 20
    risk_threshold_high: int = 50
    risk_threshold_malicious: int = 80


class SkillAnalyzer:
    """
    Main analyzer that orchestrates the SkillGuard detection pipeline.
    
    The analyzer combines:
    1. SIFA (Static Information Flow Analysis) - Deterministic component
    2. LLM Intent Audit - Probabilistic component
    3. Hybrid Scoring - Combines results with popularity metrics
    """
    
    def __init__(
        self,
        settings: Optional[Settings] = None,
        config: Optional[AnalysisConfig] = None,
    ):
        """Initialize the analyzer with settings and configuration."""
        self.settings = settings or get_settings()
        self.config = config or AnalysisConfig()
        
        # Lazy-loaded analyzers
        self._sifa_analyzer = None
        self._llm_auditor = None
        self._hybrid_scorer = None
        
        logger.info("SkillAnalyzer initialized")
    
    @property
    def sifa_analyzer(self):
        """Lazy-load SIFA analyzer."""
        if self._sifa_analyzer is None:
            from skillguard.detection.sifa import SIFAAnalyzer
            self._sifa_analyzer = SIFAAnalyzer(self.settings)
        return self._sifa_analyzer
    
    @property
    def llm_auditor(self):
        """Lazy-load LLM auditor."""
        if self._llm_auditor is None:
            from skillguard.detection.llm_audit import LLMAuditor
            self._llm_auditor = LLMAuditor(self.settings)
        return self._llm_auditor
    
    @property
    def hybrid_scorer(self):
        """Lazy-load hybrid scorer."""
        if self._hybrid_scorer is None:
            from skillguard.detection.hybrid import HybridScorer
            self._hybrid_scorer = HybridScorer(self.settings)
        return self._hybrid_scorer
    
    def analyze(self, skill: Skill) -> AnalysisResult:
        """
        Perform comprehensive analysis on a single skill.
        
        Args:
            skill: The skill to analyze
            
        Returns:
            Complete analysis result with threat profile
        """
        import time
        start_time = time.time()
        
        logger.info(f"Analyzing skill: {skill.manifest.name} ({skill.id})")
        
        # Initialize threat profile
        threat_profile = ThreatProfile(
            skill_id=skill.id,
            overall_severity=ThreatSeverity.NONE,
            risk_score=0.0,
        )
        
        sifa_findings = {}
        llm_audit = {}
        
        # Step 1: SIFA Analysis
        if self.config.enable_sifa:
            logger.debug("Running SIFA analysis...")
            sifa_result = self.sifa_analyzer.analyze(skill)
            sifa_findings = sifa_result.to_dict() if hasattr(sifa_result, 'to_dict') else sifa_result
            threat_profile.sifa_score = sifa_result.get('score', 0) if isinstance(sifa_result, dict) else getattr(sifa_result, 'score', 0)
            
            # Add SIFA indicators to threat profile
            indicators = sifa_result.get('indicators', []) if isinstance(sifa_result, dict) else getattr(sifa_result, 'indicators', [])
            for ind in indicators:
                if isinstance(ind, ThreatIndicator):
                    threat_profile.add_indicator(ind)
                elif isinstance(ind, dict):
                    threat_profile.add_indicator(ThreatIndicator(**ind))
        
        # Step 2: LLM Intent Audit
        if self.config.enable_llm_audit:
            logger.debug("Running LLM intent audit...")
            try:
                llm_result = self.llm_auditor.audit(skill)
                llm_audit = llm_result.to_dict() if hasattr(llm_result, 'to_dict') else llm_result
                threat_profile.llm_score = llm_result.get('score', 0) if isinstance(llm_result, dict) else getattr(llm_result, 'score', 0)
                
                # Add LLM indicators
                llm_indicators = llm_result.get('indicators', []) if isinstance(llm_result, dict) else getattr(llm_result, 'indicators', [])
                for ind in llm_indicators:
                    if isinstance(ind, ThreatIndicator):
                        threat_profile.add_indicator(ind)
                    elif isinstance(ind, dict):
                        threat_profile.add_indicator(ThreatIndicator(**ind))
            except Exception as e:
                logger.warning(f"LLM audit failed: {e}")
                llm_audit = {"error": str(e), "score": 0}
        
        # Step 3: Calculate popularity penalty
        popularity_score = skill.metadata.get_popularity_score()
        threat_profile.popularity_penalty = (1 - popularity_score) * 20  # Lower popularity = higher penalty
        
        # Step 4: Hybrid Scoring
        threat_profile.risk_score = self._calculate_final_score(
            threat_profile.sifa_score,
            threat_profile.llm_score,
            threat_profile.popularity_penalty,
        )
        
        # Step 5: Determine final label
        threat_profile.final_label = self._determine_label(threat_profile.risk_score)
        threat_profile.overall_severity = self._determine_severity(threat_profile)
        
        # Store result
        skill.threat_profile = threat_profile
        skill.metadata.analyzed = True
        skill.metadata.analysis_timestamp = datetime.now()
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        logger.info(
            f"Analysis complete: {skill.manifest.name} - "
            f"Risk Score: {threat_profile.risk_score:.1f} ({threat_profile.get_risk_level()})"
        )
        
        return AnalysisResult(
            skill_id=skill.id,
            skill_name=skill.manifest.name,
            threat_profile=threat_profile,
            sifa_findings=sifa_findings,
            llm_audit=llm_audit,
            analysis_time_ms=elapsed_ms,
        )
    
    async def analyze_async(self, skill: Skill) -> AnalysisResult:
        """Async version of analyze for batch processing."""
        # Run in thread pool to not block
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.analyze, skill)
    
    def analyze_batch(
        self,
        skills: List[Skill],
        max_workers: int = 4,
        progress_callback: Optional[callable] = None,
    ) -> List[AnalysisResult]:
        """
        Analyze multiple skills in parallel.
        
        Args:
            skills: List of skills to analyze
            max_workers: Number of parallel workers
            progress_callback: Optional callback(current, total) for progress
            
        Returns:
            List of analysis results
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = []
        total = len(skills)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_skill = {
                executor.submit(self.analyze, skill): skill
                for skill in skills
            }
            
            for i, future in enumerate(as_completed(future_to_skill)):
                skill = future_to_skill[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Failed to analyze {skill.manifest.name}: {e}")
                
                if progress_callback:
                    progress_callback(i + 1, total)
        
        return results
    
    def analyze_corpus(
        self,
        corpus: SkillCorpus,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Analyze an entire corpus and generate report.
        
        Args:
            corpus: The skill corpus to analyze
            output_dir: Optional directory to save results
            
        Returns:
            Summary statistics and results
        """
        from tqdm import tqdm
        
        logger.info(f"Analyzing corpus: {corpus.name} ({len(corpus.skills)} skills)")
        
        results = []
        
        for skill in tqdm(corpus.skills, desc="Analyzing skills"):
            try:
                result = self.analyze(skill)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to analyze {skill.id}: {e}")
        
        # Generate summary
        summary = self._generate_summary(results)
        
        # Save results if output directory provided
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Save individual results
            results_file = output_dir / "analysis_results.json"
            results_data = [r.to_dict() for r in results]
            results_file.write_text(json.dumps(results_data, indent=2, default=str))
            
            # Save summary
            summary_file = output_dir / "analysis_summary.json"
            summary_file.write_text(json.dumps(summary, indent=2, default=str))
            
            logger.info(f"Results saved to {output_dir}")
        
        return summary
    
    def _calculate_final_score(
        self,
        sifa_score: float,
        llm_score: float,
        popularity_penalty: float,
    ) -> float:
        """Calculate final risk score using configured weights."""
        score = (
            sifa_score * self.config.sifa_weight +
            llm_score * self.config.llm_weight +
            popularity_penalty * self.config.popularity_weight
        )
        return min(100, max(0, score))
    
    def _determine_label(self, risk_score: float) -> LabelCategory:
        """Determine label category from risk score."""
        if risk_score <= self.config.risk_threshold_suspicious:
            return LabelCategory.BENIGN
        elif risk_score <= self.config.risk_threshold_malicious:
            return LabelCategory.SUSPICIOUS
        else:
            return LabelCategory.MALICIOUS
    
    def _determine_severity(self, profile: ThreatProfile) -> ThreatSeverity:
        """Determine overall severity from threat profile."""
        if not profile.indicators:
            return ThreatSeverity.NONE
        
        # Get highest severity from indicators
        max_severity = ThreatSeverity.NONE
        for indicator in profile.indicators:
            if get_severity_score(indicator.severity) > get_severity_score(max_severity):
                max_severity = indicator.severity
        
        return max_severity
    
    def _generate_summary(self, results: List[AnalysisResult]) -> Dict[str, Any]:
        """Generate summary statistics from analysis results."""
        total = len(results)
        
        label_counts = {
            "benign": 0,
            "suspicious": 0,
            "malicious": 0,
        }
        
        category_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        avg_score = 0.0
        
        for result in results:
            profile = result.threat_profile
            
            # Label counts
            label_counts[profile.final_label.value] = (
                label_counts.get(profile.final_label.value, 0) + 1
            )
            
            # Category counts
            for cat in profile.categories_detected:
                category_counts[cat.value] = category_counts.get(cat.value, 0) + 1
            
            # Severity counts
            sev = profile.overall_severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Average score
            avg_score += profile.risk_score
        
        avg_score = avg_score / total if total > 0 else 0
        
        return {
            "total_analyzed": total,
            "label_distribution": label_counts,
            "category_distribution": category_counts,
            "severity_distribution": severity_counts,
            "average_risk_score": round(avg_score, 2),
            "high_risk_count": label_counts["suspicious"] + label_counts["malicious"],
            "detection_rate": (label_counts["suspicious"] + label_counts["malicious"]) / total if total > 0 else 0,
        }
