"""
SkillGuard CLI - Command Line Interface.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

from skillguard import __version__
from skillguard.core.skill import Skill, SkillCorpus
from skillguard.core.analyzer import SkillAnalyzer
from skillguard.config import get_settings

console = Console()


@click.group()
@click.version_option(version=__version__)
def main():
    """SkillGuard - Detecting Semantic Trojans in Agentic AI Tool Chains."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for results (JSON)")
@click.option("--no-llm", is_flag=True, help="Disable LLM audit (faster, less accurate)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def analyze(path: str, output: Optional[str], no_llm: bool, verbose: bool):
    """Analyze a skill directory or file."""
    path = Path(path)
    
    console.print(f"\n[bold blue]SkillGuard v{__version__}[/bold blue]")
    console.print(f"Analyzing: {path}\n")
    
    try:
        # Load skill
        if path.is_dir():
            skill = Skill.from_directory(path)
        else:
            # Single file - need manifest
            console.print("[yellow]Single file provided - looking for SKILL.md...[/yellow]")
            skill = Skill.from_directory(path.parent)
        
        # Configure analyzer
        from skillguard.core.analyzer import AnalysisConfig
        config = AnalysisConfig(enable_llm_audit=not no_llm)
        analyzer = SkillAnalyzer(config=config)
        
        # Run analysis
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            progress.add_task("Running analysis...", total=None)
            result = analyzer.analyze(skill)
        
        # Display results
        _display_analysis_result(result, verbose)
        
        # Save if output specified
        if output:
            Path(output).write_text(result.to_json())
            console.print(f"\n[green]Results saved to {output}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("corpus_path", type=click.Path(exists=True))
@click.option("--output-dir", "-o", type=click.Path(), default="./output", help="Output directory")
@click.option("--max-workers", "-w", type=int, default=4, help="Parallel workers")
def scan(corpus_path: str, output_dir: str, max_workers: int):
    """Scan an entire corpus of skills."""
    from skillguard.core.skill import SkillCorpus
    
    console.print(f"\n[bold blue]SkillGuard Corpus Scan[/bold blue]")
    
    corpus_path = Path(corpus_path)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load corpus from directory
    corpus = SkillCorpus()
    for skill_dir in corpus_path.iterdir():
        if skill_dir.is_dir():
            try:
                skill = Skill.from_directory(skill_dir)
                corpus.add_skill(skill)
            except:
                pass
    
    console.print(f"Loaded {len(corpus.skills)} skills")
    
    analyzer = SkillAnalyzer()
    summary = analyzer.analyze_corpus(corpus, output_path)
    
    # Display summary
    table = Table(title="Analysis Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in summary.items():
        if isinstance(value, dict):
            for k, v in value.items():
                table.add_row(f"  {k}", str(v))
        else:
            table.add_row(key, str(value))
    
    console.print(table)


@main.command()
@click.option("--query", "-q", type=str, multiple=True, help="Search queries")
@click.option("--max-repos", "-n", type=int, default=50, help="Max repos per query")
@click.option("--output", "-o", type=click.Path(), default="./data/corpus.json", help="Output file")
def scrape(query: tuple, max_repos: int, output: str):
    """Scrape GitHub for skills."""
    from skillguard.acquisition.scraper import GitHubScraper
    
    console.print("[bold blue]SkillGuard GitHub Scraper[/bold blue]\n")
    
    scraper = GitHubScraper()
    
    if query:
        scraper.SEARCH_QUERIES = list(query)
    
    with Progress(console=console) as progress:
        task = progress.add_task("Scraping...", total=None)
        corpus = scraper.scrape_all(max_per_query=max_repos)
    
    # Save corpus
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    corpus.save(output_path)
    
    console.print(f"\n[green]Scraped {len(corpus.skills)} skills[/green]")
    console.print(f"Saved to: {output_path}")
    
    # Show stats
    stats = corpus.get_statistics()
    console.print(f"\nCategories: {stats['categories']}")
    console.print(f"Languages: {stats['languages']}")


@main.command()
@click.argument("corpus_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for evaluation results")
def evaluate(corpus_path: str, output: Optional[str]):
    """Evaluate SkillGuard on labeled corpus."""
    from skillguard.evaluation import Evaluator, BaselineComparator
    
    console.print("[bold blue]SkillGuard Evaluation[/bold blue]\n")
    
    # Load labeled corpus
    corpus = SkillCorpus.load(Path(corpus_path))
    labeled = corpus.get_labeled_subset()
    
    if not labeled:
        console.print("[red]No labeled skills found in corpus[/red]")
        return
    
    console.print(f"Evaluating on {len(labeled)} labeled skills\n")
    
    # Run evaluation
    evaluator = Evaluator()
    results = evaluator.evaluate(labeled)
    
    # Show results
    metrics = results["overall_metrics"]
    table = Table(title="Evaluation Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Precision", f"{metrics['precision']:.2%}")
    table.add_row("Recall", f"{metrics['recall']:.2%}")
    table.add_row("F1 Score", f"{metrics['f1_score']:.2%}")
    table.add_row("Accuracy", f"{metrics['accuracy']:.2%}")
    
    console.print(table)
    
    # Baseline comparison
    console.print("\n[bold]Baseline Comparison:[/bold]")
    comparator = BaselineComparator()
    baselines = comparator.compare(labeled)
    
    for name, baseline_metrics in baselines.items():
        console.print(f"  {name}: F1={baseline_metrics['f1_score']:.2%}")
    
    if output:
        Path(output).write_text(json.dumps(results, indent=2))


@main.command()
@click.option("--count", "-n", type=int, default=50, help="Number of samples")
@click.option("--output", "-o", type=click.Path(), default="./data/redteam.json")
def redteam(count: int, output: str):
    """Generate synthetic malicious samples for testing."""
    from skillguard.evaluation import RedTeamGenerator
    
    console.print("[bold red]Red Team Sample Generator[/bold red]\n")
    
    generator = RedTeamGenerator()
    samples = generator.generate_all()
    
    console.print(f"Generated {len(samples)} malicious samples")
    
    # Save
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    data = [s.to_dict() for s in samples]
    output_path.write_text(json.dumps(data, indent=2))
    
    console.print(f"Saved to: {output_path}")


def _display_analysis_result(result, verbose: bool = False):
    """Display analysis result in rich format."""
    profile = result.threat_profile
    
    # Risk level color
    level_colors = {
        "BENIGN": "green",
        "SUSPICIOUS": "yellow", 
        "HIGH-RISK": "orange1",
        "MALICIOUS": "red",
    }
    level = profile.get_risk_level()
    color = level_colors.get(level, "white")
    
    # Header panel
    console.print(Panel(
        f"[bold]{result.skill_name}[/bold]\n"
        f"Risk Score: [{color}]{profile.risk_score:.1f}/100[/{color}]\n"
        f"Risk Level: [{color}]{level}[/{color}]",
        title="Analysis Result"
    ))
    
    # Score breakdown
    console.print("\n[bold]Score Breakdown:[/bold]")
    console.print(f"  SIFA Score: {profile.sifa_score:.1f}")
    console.print(f"  LLM Score: {profile.llm_score:.1f}")
    console.print(f"  Popularity Penalty: {profile.popularity_penalty:.1f}")
    
    # Threat indicators
    if profile.indicators:
        console.print(f"\n[bold]Threat Indicators ({len(profile.indicators)}):[/bold]")
        
        table = Table()
        table.add_column("Severity", style="bold")
        table.add_column("Category")
        table.add_column("Description")
        
        for ind in profile.indicators[:10]:  # Show max 10
            sev_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue"}.get(ind.severity.value, "white")
            table.add_row(
                f"[{sev_color}]{ind.severity.value.upper()}[/{sev_color}]",
                ind.category.value,
                ind.description[:60] + "..." if len(ind.description) > 60 else ind.description
            )
        
        console.print(table)
    else:
        console.print("\n[green]No threat indicators detected[/green]")
    
    # Timing
    console.print(f"\n[dim]Analysis completed in {result.analysis_time_ms:.0f}ms[/dim]")


if __name__ == "__main__":
    main()
