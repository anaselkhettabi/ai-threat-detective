import os
import sys
import time
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

load_dotenv()

console = Console(stderr=True)


def _print_cluster_summary(clusters) -> None:
    table = Table(title="Correlated Event Clusters", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Score", style="bold")
    table.add_column("Actor", max_width=40)
    table.add_column("Target", max_width=40)
    table.add_column("Events", justify="right")
    table.add_column("Tags")
    for c in clusters:
        score_style = "red" if c.suspicion_score >= 8 else "yellow" if c.suspicion_score >= 5 else "green"
        table.add_row(
            c.cluster_id,
            f"[{score_style}]{c.suspicion_score:.1f}[/{score_style}]",
            c.primary_actor[:40],
            c.primary_target[:40],
            str(len(c.events)),
            ", ".join(c.tags) or "—",
        )
    console.print(table)


@click.group()
def cli():
    """AI Threat Detective — Agentic security log analyzer."""


@cli.command()
@click.option("--file", "files", multiple=True, required=True,
              type=click.Path(exists=True), help="Log file(s) to analyze.")
@click.option("--output", "output_format",
              type=click.Choice(["json", "markdown", "both"]), default="both",
              show_default=True, help="Report output format.")
@click.option("--out-file", "out_file", default=None,
              help="Write report to this path prefix (omit for stdout).")
@click.option("--max-rounds", default=3, show_default=True,
              help="Maximum agentic investigation rounds.")
@click.option("--top-n", default=5, show_default=True,
              help="Number of top clusters to surface to the LLM.")
def analyze(files, output_format, out_file, max_rounds, top_n):
    """Analyze one or more log files and produce an incident report."""
    from parsers import detect_parser
    from core.correlator import correlate
    from core.agent import investigate
    from core.reporter import generate
    from core.llm import get_llm_client, LLMError

    all_events = []
    for file_path in files:
        console.print(f"[cyan]Parsing[/cyan] {file_path}")
        try:
            parser_cls = detect_parser(file_path)
            parser = parser_cls()
            events = parser.parse(file_path)
            console.print(f"  → {len(events)} events ({parser_cls.__name__})")
            all_events.extend(events)
        except Exception as e:
            console.print(f"[red]Error parsing {file_path}:[/red] {e}")
            sys.exit(1)

    if not all_events:
        console.print("[yellow]No events parsed. Exiting.[/yellow]")
        sys.exit(0)

    console.print(f"\n[cyan]Correlating[/cyan] {len(all_events)} events...")
    clusters = correlate(all_events, top_n=top_n)
    console.print(f"  → {len(clusters)} cluster(s) found\n")
    _print_cluster_summary(clusters)

    try:
        llm = get_llm_client()
    except (ValueError, Exception) as e:
        console.print(f"[red]LLM setup error:[/red] {e}")
        sys.exit(1)

    console.print(f"\n[cyan]Investigating[/cyan] with {llm.__class__.__name__} ({llm.model})...")

    round_holder = [0]

    def on_progress(current_round: int, total_rounds: int) -> None:
        round_holder[0] = current_round
        console.print(f"  [dim][Round {current_round}/{total_rounds}] Analyzing clusters...[/dim]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  console=console, transient=True) as progress:
        task = progress.add_task("Running investigation...", total=None)
        try:
            result = investigate(clusters, all_events, llm, max_rounds, on_progress)
        except LLMError as e:
            console.print(f"[red]LLM error:[/red] {e}")
            sys.exit(1)
        progress.update(task, description="Done")

    console.print(f"\n[green]Investigation complete[/green] ({result.rounds_used} round(s))")
    console.print(f"MITRE techniques: {', '.join(result.mitre_techniques) or 'none identified'}")

    data = generate(result, output_format, out_file)
    severity_colors = {"Critical": "red", "High": "yellow", "Medium": "cyan", "Low": "green"}
    color = severity_colors.get(data["severity"], "white")
    console.print(f"\nSeverity: [{color}]{data['severity']}[/{color}]")
    if out_file:
        console.print(f"Report written to: {out_file}")


@cli.command()
@click.option("--dir", "watch_dir", required=True, type=click.Path(exists=True),
              help="Directory to watch for new log files.")
@click.option("--interval", default=30, show_default=True, help="Poll interval in seconds.")
@click.option("--output", "output_format",
              type=click.Choice(["json", "markdown", "both"]), default="both")
@click.option("--out-dir", "out_dir", default="output",
              help="Directory to write timestamped reports.")
def watch(watch_dir, interval, output_format, out_dir):
    """Watch a directory and analyze new log files as they appear."""
    from parsers import detect_parser
    from core.correlator import correlate
    from core.agent import investigate
    from core.reporter import generate
    from core.llm import get_llm_client, LLMError

    Path(out_dir).mkdir(parents=True, exist_ok=True)

    try:
        llm = get_llm_client()
    except Exception as e:
        console.print(f"[red]LLM setup error:[/red] {e}")
        sys.exit(1)

    seen_mtimes: dict[str, float] = {}
    console.print(f"[cyan]Watching[/cyan] {watch_dir} every {interval}s...")

    while True:
        new_events = []
        watch_path = Path(watch_dir)
        for f in watch_path.rglob("*"):
            if not f.is_file():
                continue
            try:
                mtime = f.stat().st_mtime
            except OSError:
                continue
            if seen_mtimes.get(str(f)) == mtime:
                continue
            seen_mtimes[str(f)] = mtime
            try:
                parser_cls = detect_parser(str(f))
                events = parser_cls().parse(str(f))
                new_events.extend(events)
                console.print(f"  [cyan]+{len(events)} events[/cyan] from {f.name}")
            except Exception:
                pass

        if new_events:
            clusters = correlate(new_events)
            _print_cluster_summary(clusters)
            try:
                result = investigate(clusters, new_events, llm)
                ts = time.strftime("%Y%m%d_%H%M%S")
                out_prefix = str(Path(out_dir) / f"report_{ts}")
                generate(result, output_format, out_prefix)
                console.print(f"Report written: {out_prefix}")
            except LLMError as e:
                console.print(f"[red]LLM error:[/red] {e}")

        time.sleep(interval)


@cli.command("test-connection")
def test_connection():
    """Verify the configured LLM provider is reachable."""
    from core.llm import get_llm_client, LLMError

    try:
        llm = get_llm_client()
    except Exception as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Provider: {llm.__class__.__name__}")
    click.echo(f"Model:    {llm.model}")
    click.echo("Sending probe...")

    try:
        response = llm.complete(
            system="You are a test assistant.",
            user="Reply with exactly the word OK and nothing else.",
        )
        if "ok" in response.lower():
            click.echo("Status:   OK")
        else:
            click.echo(f"Status:   Unexpected response: {response[:100]!r}")
    except LLMError as e:
        click.echo(f"Status:   FAILED — {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
