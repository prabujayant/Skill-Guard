"""
Integrated data collection script.

Combines:
- Upskill-generated skills (benign)
- GitHub-scraped MCP tools (benign)
- Synthetic malicious variants

Generates 1000+ skills for SkillGuard training.
"""

import argparse
from pathlib import Path
from loguru import logger
import json

from skillguard.acquisition.upskill_importer import UpskillImporter
from skillguard.acquisition.malicious_generator import MaliciousSkillGenerator
from skillguard.core.skill import Skill


def main():
    parser = argparse.ArgumentParser(description="Collect dataset for SkillGuard")
    parser.add_argument("--benign-count", type=int, default=800, help="Number of benign skills")
    parser.add_argument(
        "--malicious-count", type=int, default=200, help="Number of malicious skills"
    )
    parser.add_argument("--output-dir", type=Path, default=Path("./data"), help="Output directory")
    parser.add_argument(
        "--upskill-ratio",
        type=float,
        default=0.6,
        help="Ratio of benign skills from Upskill (rest from GitHub)",
    )
    parser.add_argument("--skip-upskill", action="store_true", help="Skip Upskill generation")
    parser.add_argument("--skip-github", action="store_true", help="Skip GitHub scraping")
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    benign_skills = []
    malicious_skills = []
    
    # ========== Benign Skills ==========
    
    logger.info("=" * 60)
    logger.info("COLLECTING BENIGN SKILLS")
    logger.info("=" * 60)
    
    upskill_count = int(args.benign_count * args.upskill_ratio)
    github_count = args.benign_count - upskill_count
    
    # 1. Generate from Upskill
    if not args.skip_upskill:
        logger.info(f"\n📦 Generating {upskill_count} skills with Upskill...")
        
        importer = UpskillImporter(output_dir=output_dir / "upskill")
        
        # Generate diverse tasks
        tasks = importer.generate_diverse_task_list(count=upskill_count)
        
        # Generate skills
        upskill_skills = importer.generate_benign_skills(
            tasks=tasks[:upskill_count],
            model="anthropic/claude-sonnet-4-20250514",
            eval_model="anthropic/claude-haiku-4-20250112"
        )
        
        benign_skills.extend(upskill_skills)
        logger.info(f"✓ Generated {len(upskill_skills)} Upskill skills")
    
    # 2. Scrape from GitHub
    if not args.skip_github:
        logger.info(f"\n🌐 Scraping {github_count} skills from GitHub...")
        
        importer = UpskillImporter()
        github_skills = importer.import_from_github(
            repo_patterns=[
                "*/mcp-server-*",
                "*/langchain-*",
                "*agent-skill*",
                "*mcp-*"
            ],
            max_repos=github_count
        )
        
        benign_skills.extend(github_skills[:github_count])
        logger.info(f"✓ Scraped {len(github_skills[:github_count])} GitHub skills")
    
    # ========== Malicious Skills ==========
    
    logger.info("\n" + "=" * 60)
    logger.info("GENERATING MALICIOUS SKILLS")
    logger.info("=" * 60)
    
    generator = MaliciousSkillGenerator(output_dir=output_dir / "malicious")
    
    # Generate malicious variants
    malicious_skills = generator.generate_malicious_variants(
        benign_templates=benign_skills[:50],  # Use first 50 as templates
        target_count=args.malicious_count,
        threat_distribution={
            "arbitrary_code_execution": 0.25,
            "data_exfiltration": 0.25,
            "reverse_shell": 0.15,
            "privilege_escalation": 0.15,
            "semantic_mismatch": 0.15,
            "supply_chain_injection": 0.05,
        }
    )
    
    logger.info(f"✓ Generated {len(malicious_skills)} malicious skills")
    
    # ========== Save Dataset ==========
    
    logger.info("\n" + "=" * 60)
    logger.info("SAVING DATASET")
    logger.info("=" * 60)
    
    # Save benign
    benign_dir = output_dir / "benign"
    benign_dir.mkdir(exist_ok=True)
    
    for i, skill in enumerate(benign_skills):
        skill_path = benign_dir / f"skill_{i:04d}"
        skill.save(skill_path)
    
    # Save malicious
    malicious_dir = output_dir / "malicious"
    malicious_dir.mkdir(exist_ok=True)
    
    for i, skill in enumerate(malicious_skills):
        skill_path = malicious_dir / f"skill_{i:04d}"
        skill.save(skill_path)
    
    # Create metadata
    metadata = {
        "total_skills": len(benign_skills) + len(malicious_skills),
        "benign_count": len(benign_skills),
        "malicious_count": len(malicious_skills),
        "benign_sources": {
            "upskill": len([s for s in benign_skills if s.metadata.get("source") == "upskill"]),
            "github": len([s for s in benign_skills if s.metadata.get("source") == "github"]),
        },
        "malicious_categories": {
            cat: len([s for s in malicious_skills if cat in s.metadata.get("threats", [])])
            for cat in [
                "arbitrary_code_execution",
                "data_exfiltration",
                "reverse_shell",
                "privilege_escalation",
                "semantic_mismatch",
                "supply_chain_injection",
            ]
        },
    }
    
    (output_dir / "dataset_metadata.json").write_text(json.dumps(metadata, indent=2))
    
    logger.info("\n✅ Dataset collection complete!")
    logger.info(f"Total skills: {metadata['total_skills']}")
    logger.info(f"  - Benign: {metadata['benign_count']}")
    logger.info(f"  - Malicious: {metadata['malicious_count']}")
    logger.info(f"Saved to: {output_dir}")


if __name__ == "__main__":
    main()
