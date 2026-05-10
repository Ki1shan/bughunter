from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.spinner import Spinner

console = Console(force_terminal=True, legacy_windows=False)
error_console = Console(stderr=True, force_terminal=True, legacy_windows=False)


def make_progress():
    return Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


def print_banner():
    console.print(Panel(
        "[bold green]BugHunter AI[/bold green] [dim]v2.0 Elite[/dim]\n"
        "[cyan]Advanced Security Analysis Engine[/cyan]",
        box=box.DOUBLE,
        border_style="green",
        padding=(1, 2),
    ))


def print_phase(phase_num, name, detail=None):
    console.print(f"\n[bold blue][Phase {phase_num}][/bold blue] [white]{name}[/white]")
    if detail:
        console.print(f"  [dim]{detail}[/dim]")


def print_step(icon, text, style="white"):
    console.print(f"  [{style}]{icon}[/] {text}")


def print_finding(vuln_type, param, severity, confidence, endpoint=""):
    colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green"}
    color = colors.get(severity, "white")
    icons = {"confirmed": "[+]", "likely": "[~]", "suspected": "[?]", "rejected": "[-]"}
    icon = icons.get(confidence, "[?]")

    endpoint_str = f" @ {endpoint}" if endpoint else ""
    console.print(f"    {icon} [{color}]{vuln_type.upper()}[/] on [cyan]{param}[/]{endpoint_str} [dim]({severity})[/dim]")


def print_summary_table(summary, duration, attack_surface, ai_plan):
    table = Table(title="Scan Summary", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Metric", style="white")
    table.add_column("Value", style="bold")

    table.add_row("Endpoints Scanned", str(summary.get("total_endpoints_scanned", 0)))
    table.add_row("Duration", f"{duration:.1f}s")
    table.add_row("Critical Issues", f"[red]{summary.get('critical_issues', 0)}[/red]")
    table.add_row("High Issues", f"[bright_red]{summary.get('high_issues', 0)}[/bright_red]")
    table.add_row("Medium Issues", f"[yellow]{summary.get('medium_issues', 0)}[/yellow]")
    table.add_row("Low Issues", f"[green]{summary.get('low_issues', 0)}[/green]")
    table.add_row("Attack Chains", str(summary.get("total_chains", 0)))

    console.print(table)

    surface = attack_surface or {}
    surface_table = Table(title="Attack Surface", box=box.ROUNDED, header_style="bold cyan")
    surface_table.add_column("Source", style="white")
    surface_table.add_column("Count", style="bold")

    surface_table.add_row("Subdomains", str(len(surface.get("subdomains", []))))
    surface_table.add_row("API Routes", str(len(surface.get("api_endpoints", []))))
    surface_table.add_row("Hidden Routes", str(len(surface.get("hidden_routes", []))))
    surface_table.add_row("JS Discovered", str(len(surface.get("js_discovered", []))))

    console.print(surface_table)

    if ai_plan and ai_plan.get("attack_phases"):
        plan_table = Table(title="AI Attack Plan", box=box.ROUNDED, header_style="bold cyan")
        plan_table.add_column("Phase", style="bold blue")
        plan_table.add_column("Name", style="white")
        plan_table.add_column("Priority", style="yellow")

        for phase in ai_plan["attack_phases"][:5]:
            plan_table.add_row(
                str(phase.get("phase", "?")),
                phase.get("name", "Unknown"),
                str(phase.get("priority", "N/A")),
            )
        console.print(plan_table)


def print_completion():
    console.print(Panel(
        "[bold green]Scan Complete![/bold green]\n"
        "[dim]Reports:[/dim] [cyan]output/dashboard.html[/cyan] | [cyan]output/bughunter_report.html[/cyan]\n"
        "[dim]Learning DB:[/dim] [cyan]learning_db.json[/cyan] (updated)",
        box=box.DOUBLE,
        border_style="green",
        padding=(1, 2),
    ))
