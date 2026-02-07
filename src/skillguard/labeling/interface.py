"""
Ground-Truth Labeling Interface for manual annotation of skills.

This module provides tools for security experts to manually label skills
and calculate inter-rater agreement (Fleiss' Kappa).
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from skillguard.core.skill import Skill, SkillCorpus
from skillguard.taxonomy import LabelCategory, ThreatCategory


@dataclass
class AnnotationRecord:
    """A single annotation by a labeler."""
    skill_id: str
    labeler_id: str
    label: LabelCategory
    threat_categories: List[ThreatCategory] = field(default_factory=list)
    confidence: float = 1.0
    notes: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "labeler_id": self.labeler_id,
            "label": self.label.value,
            "threat_categories": [c.value for c in self.threat_categories],
            "confidence": self.confidence,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class LabelingSession:
    """A labeling session with multiple annotators."""
    session_id: str
    skills: List[Skill]
    annotations: List[AnnotationRecord] = field(default_factory=list)
    labelers: List[str] = field(default_factory=list)
    
    def add_annotation(self, annotation: AnnotationRecord) -> None:
        """Add an annotation to the session."""
        self.annotations.append(annotation)
        if annotation.labeler_id not in self.labelers:
            self.labelers.append(annotation.labeler_id)
    
    def get_annotations_for_skill(self, skill_id: str) -> List[AnnotationRecord]:
        """Get all annotations for a specific skill."""
        return [a for a in self.annotations if a.skill_id == skill_id]
    
    def calculate_fleiss_kappa(self) -> float:
        """
        Calculate Fleiss' Kappa for inter-rater agreement.
        
        Returns:
            Kappa score (-1 to 1, where 1 is perfect agreement)
        """
        if len(self.labelers) < 2:
            return 1.0
        
        # Build rating matrix
        categories = [LabelCategory.BENIGN, LabelCategory.SUSPICIOUS, LabelCategory.MALICIOUS]
        n_categories = len(categories)
        n_subjects = len(self.skills)
        n_raters = len(self.labelers)
        
        # Matrix: subjects x categories (count of raters who assigned each category)
        matrix = [[0] * n_categories for _ in range(n_subjects)]
        
        for i, skill in enumerate(self.skills):
            skill_annotations = self.get_annotations_for_skill(skill.id)
            for ann in skill_annotations:
                cat_idx = categories.index(ann.label) if ann.label in categories else 0
                matrix[i][cat_idx] += 1
        
        # Calculate Fleiss' Kappa
        # P_j: proportion of ratings in each category
        P_j = []
        total_ratings = n_subjects * n_raters
        for j in range(n_categories):
            count = sum(matrix[i][j] for i in range(n_subjects))
            P_j.append(count / total_ratings if total_ratings > 0 else 0)
        
        # P_i: extent of agreement for each subject
        P_i = []
        for i in range(n_subjects):
            sum_squared = sum(matrix[i][j] ** 2 for j in range(n_categories))
            P_i.append((sum_squared - n_raters) / (n_raters * (n_raters - 1)) if n_raters > 1 else 0)
        
        # P_bar: mean of P_i
        P_bar = sum(P_i) / n_subjects if n_subjects > 0 else 0
        
        # P_e: expected agreement
        P_e = sum(p ** 2 for p in P_j)
        
        # Kappa
        if P_e == 1:
            return 1.0
        kappa = (P_bar - P_e) / (1 - P_e)
        
        return kappa
    
    def resolve_disagreements(self, arbitrator_id: str = "arbitrator") -> None:
        """
        Resolve disagreements between annotators by majority vote.
        Ties are resolved by the arbitrator if provided.
        """
        for skill in self.skills:
            annotations = self.get_annotations_for_skill(skill.id)
            if not annotations:
                continue
            
            # Count votes
            votes = {label: 0 for label in LabelCategory}
            for ann in annotations:
                votes[ann.label] += 1
            
            # Find majority
            max_votes = max(votes.values())
            winners = [label for label, count in votes.items() if count == max_votes]
            
            # Assign final label
            if len(winners) == 1:
                skill.metadata.label = winners[0]
            else:
                # Tie - use most severe
                severity_order = [LabelCategory.MALICIOUS, LabelCategory.SUSPICIOUS, LabelCategory.BENIGN]
                for label in severity_order:
                    if label in winners:
                        skill.metadata.label = label
                        break
            
            skill.metadata.labeler_id = "consensus"
            skill.metadata.label_confidence = max_votes / len(annotations) if annotations else 0
    
    def save(self, filepath: Path) -> None:
        """Save session to JSON file."""
        data = {
            "session_id": self.session_id,
            "labelers": self.labelers,
            "annotations": [a.to_dict() for a in self.annotations],
            "fleiss_kappa": self.calculate_fleiss_kappa(),
        }
        filepath.write_text(json.dumps(data, indent=2))
    
    @classmethod
    def load(cls, filepath: Path) -> "LabelingSession":
        """Load session from JSON file."""
        data = json.loads(filepath.read_text())
        session = cls(session_id=data["session_id"], skills=[])
        session.labelers = data["labelers"]
        for ann_data in data["annotations"]:
            session.annotations.append(AnnotationRecord(
                skill_id=ann_data["skill_id"],
                labeler_id=ann_data["labeler_id"],
                label=LabelCategory(ann_data["label"]),
                threat_categories=[ThreatCategory(c) for c in ann_data.get("threat_categories", [])],
                confidence=ann_data.get("confidence", 1.0),
                notes=ann_data.get("notes", ""),
            ))
        return session


class LabelingCLI:
    """Command-line interface for manual labeling."""
    
    THREAT_CATEGORY_DESCRIPTIONS = {
        ThreatCategory.ARBITRARY_CODE_EXECUTION: "Executes arbitrary commands (eval, exec, subprocess)",
        ThreatCategory.DATA_EXFILTRATION: "Sends sensitive data to external servers",
        ThreatCategory.REVERSE_SHELL: "Creates reverse shell connection",
        ThreatCategory.PRIVILEGE_ESCALATION: "Accesses resources beyond declared scope",
        ThreatCategory.SEMANTIC_MISMATCH: "Description doesn't match actual behavior",
        ThreatCategory.SUPPLY_CHAIN_INJECTION: "Hidden/obfuscated malicious code",
    }
    
    def __init__(self, labeler_id: str):
        self.labeler_id = labeler_id
        self.session: Optional[LabelingSession] = None
    
    def start_session(self, skills: List[Skill]) -> LabelingSession:
        """Start a new labeling session."""
        import uuid
        self.session = LabelingSession(
            session_id=str(uuid.uuid4())[:8],
            skills=skills,
        )
        return self.session
    
    def label_skill(self, skill: Skill) -> AnnotationRecord:
        """Interactively label a single skill."""
        print("\n" + "="*60)
        print(f"SKILL: {skill.manifest.name}")
        print("="*60)
        print(f"\nDescription: {skill.manifest.description[:200]}...")
        print(f"\nDeclared Capabilities: {', '.join(skill.manifest.declared_capabilities) or 'None'}")
        print(f"Declared Permissions: {', '.join(skill.manifest.declared_permissions) or 'None'}")
        print(f"\nCode ({skill.code.filename}, {skill.code.line_count} lines):")
        print("-"*40)
        # Show first 30 lines
        lines = skill.code.content.split('\n')[:30]
        for i, line in enumerate(lines, 1):
            print(f"{i:3}: {line}")
        if len(skill.code.content.split('\n')) > 30:
            print("... (truncated)")
        print("-"*40)
        
        # Get label
        print("\nLabels:")
        print("  1. BENIGN - Code matches declared functionality")
        print("  2. SUSPICIOUS - Minor red flags, unclear intent")
        print("  3. MALICIOUS - Clear security violations")
        
        while True:
            choice = input("\nYour label (1/2/3): ").strip()
            if choice == "1":
                label = LabelCategory.BENIGN
                break
            elif choice == "2":
                label = LabelCategory.SUSPICIOUS
                break
            elif choice == "3":
                label = LabelCategory.MALICIOUS
                break
            print("Invalid choice")
        
        # Get threat categories if not benign
        threat_categories = []
        if label != LabelCategory.BENIGN:
            print("\nThreat Categories (comma-separated numbers):")
            for i, (cat, desc) in enumerate(self.THREAT_CATEGORY_DESCRIPTIONS.items(), 1):
                print(f"  {i}. {cat.value}: {desc}")
            
            cats_input = input("\nCategories: ").strip()
            if cats_input:
                cat_list = list(self.THREAT_CATEGORY_DESCRIPTIONS.keys())
                for num in cats_input.split(","):
                    try:
                        idx = int(num.strip()) - 1
                        if 0 <= idx < len(cat_list):
                            threat_categories.append(cat_list[idx])
                    except:
                        pass
        
        # Get confidence
        conf_input = input("\nConfidence (0.0-1.0, default 1.0): ").strip()
        confidence = float(conf_input) if conf_input else 1.0
        
        # Get notes
        notes = input("\nNotes (optional): ").strip()
        
        annotation = AnnotationRecord(
            skill_id=skill.id,
            labeler_id=self.labeler_id,
            label=label,
            threat_categories=threat_categories,
            confidence=confidence,
            notes=notes,
        )
        
        if self.session:
            self.session.add_annotation(annotation)
        
        return annotation
    
    def run(self, skills: List[Skill], output_path: Optional[Path] = None) -> LabelingSession:
        """Run full labeling session."""
        session = self.start_session(skills)
        
        print(f"\nLabeling Session: {session.session_id}")
        print(f"Labeler: {self.labeler_id}")
        print(f"Skills to label: {len(skills)}")
        
        for i, skill in enumerate(skills, 1):
            print(f"\n[{i}/{len(skills)}]")
            self.label_skill(skill)
        
        if output_path:
            session.save(output_path)
            print(f"\nSession saved to {output_path}")
        
        return session
