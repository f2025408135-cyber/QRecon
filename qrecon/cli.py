import json
import os
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from dotenv import load_dotenv

from qrecon.platform_enum.ibm import IBMQuantumEnumerator
from qrecon.platform_enum.braket import BraketEnumerator
from qrecon.auth_probe.token_scope import TokenScopeProber
from qrecon.auth_probe.cross_tenant import CrossTenantProber
from qrecon.auth_probe.rate_limits import RateLimitProber
from qrecon.auth_probe.credential_leak import CredentialLeakScanner
from qrecon.circuit_lens.parser import CircuitParser
from qrecon.circuit_lens.timing_oracle import TimingOracleDetector
from qrecon.circuit_lens.disclosure_heuristics import DisclosureHeuristicAnalyzer
from qrecon.circuit_lens.models import CircuitAnalysisResult
from qrecon.qhypo.agent import QHypoAgent
from qrecon.q_attck.loader import QuantumATTCKLoader

load_dotenv()
app = typer.Typer(help="QRecon — Offensive Security Reconnaissance Framework for Quantum Cloud Infrastructure")
attck_app = typer.Typer(help="Q-ATT&CK commands")
circuit_app = typer.Typer(help="Circuit analysis commands")

app.add_typer(attck_app, name="attck")
app.add_typer(circuit_app, name="circuit")

console = Console()

def get_credentials(platform: str) -> dict:
    creds = {}
    if platform == "ibm":
        token = os.getenv("IBM_QUANTUM_TOKEN")
        if not token:
            console.print("[red]Error:[/red] IBM_QUANTUM_TOKEN environment variable not set.")
            raise typer.Exit(code=1)
        creds["ibm_token"] = token
    elif platform == "braket":
        key = os.getenv("AWS_ACCESS_KEY_ID")
        secret = os.getenv("AWS_SECRET_ACCESS_KEY")
        if not key or not secret:
            console.print("[red]Error:[/red] AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY environment variables not set.")
            raise typer.Exit(code=1)
        creds["aws_access_key_id"] = key
        creds["aws_secret_access_key"] = secret
    else:
        console.print(f"[red]Error:[/red] Unsupported platform: {platform}")
        raise typer.Exit(code=1)
    return creds

@app.command()
def enum(platform: str = typer.Option(..., help="Platform to enumerate (ibm, braket)"),
         output: str = typer.Option("report.json", help="Output JSON file")):
    creds = get_credentials(platform)
    
    with Progress() as progress:
        task = progress.add_task(f"[cyan]Enumerating {platform}...", total=100)
        
        if platform == "ibm":
            enumerator_ibm = IBMQuantumEnumerator(creds["ibm_token"])
            progress.update(task, advance=50)
            result = enumerator_ibm.enumerate()
        else:
            enumerator_braket = BraketEnumerator(creds["aws_access_key_id"], creds["aws_secret_access_key"])
            progress.update(task, advance=50)
            result = enumerator_braket.enumerate()
        
        progress.update(task, advance=50)
        
    with open(output, "w") as f:
        f.write(result.model_dump_json(indent=2))
        
    console.print(f"[green]Enumeration complete![/green] Found [bold]{len(result.backends)}[/bold] backends.")
    console.print(f"Results saved to [bold]{output}[/bold]")

@app.command()
def auth(platform: str = typer.Option(..., help="Platform to test (ibm, braket)"),
         output: str = typer.Option("report.json", help="Output JSON file")):
    creds = get_credentials(platform)
    full_platform = "ibm-quantum" if platform == "ibm" else "amazon-braket"
    
    results = {}
    with Progress() as progress:
        task = progress.add_task(f"[cyan]Running Auth Probes on {platform}...", total=100)
        
        # Token Scope
        prober = TokenScopeProber(full_platform, creds)
        results["token_scope"] = prober.probe().model_dump()
        progress.update(task, advance=30)
        
        # Rate Limits
        rl_prober = RateLimitProber(full_platform, creds)
        results["rate_limits"] = rl_prober.probe().model_dump()
        progress.update(task, advance=30)
        
        # Cross Tenant (IBM only for now, and mocked in CLI to avoid accidental real damage)
        if platform == "ibm":
             ct_prober = CrossTenantProber(creds["ibm_token"])
             results["cross_tenant"] = ct_prober.probe(prompt_user=False).model_dump()
        progress.update(task, advance=40)
        
    with open(output, "w") as f:
        json.dump(results, f, indent=2, default=str)
        
    console.print("[green]Auth probes complete![/green]")
    console.print(f"Results saved to [bold]{output}[/bold]")

@circuit_app.command("analyze")
def analyze_circuit(file: str = typer.Option(..., help="Path to QASM file to analyze")):
    if not os.path.exists(file):
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(code=1)
        
    parser = CircuitParser()
    try:
        parsed = parser.parse_file(file)
    except Exception as e:
        console.print(f"[red]Error parsing circuit:[/red] {str(e)}")
        raise typer.Exit(code=1)
        
    t_detector = TimingOracleDetector()
    d_analyzer = DisclosureHeuristicAnalyzer()
    
    t_result = t_detector.analyze(parsed)
    d_result = d_analyzer.analyze(parsed)
    
    all_findings = t_result.findings + d_result.findings
    
    result = CircuitAnalysisResult(
        circuit_name=os.path.basename(file),
        parsed_metrics=parsed,
        findings=all_findings
    )
    
    console.print(result.model_dump_json(indent=2))

@app.command("scan-credentials")
def scan_credentials(output: str = typer.Option("report.json", help="Output JSON file")):
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        console.print("[red]Error:[/red] GITHUB_TOKEN environment variable not set.")
        raise typer.Exit(code=1)
        
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning GitHub for credentials...", total=None)
        scanner = CredentialLeakScanner(token)
        result = scanner.scan()
        progress.update(task, completed=100)
        
    with open(output, "w") as f:
        f.write(result.model_dump_json(indent=2))
        
    console.print(f"[green]Scan complete![/green] Found [bold red]{len(result.findings)}[/bold red] potential leaks.")
    console.print(f"[yellow]{result.disclaimer}[/yellow]")
    console.print(f"Results saved to [bold]{output}[/bold]")

@app.command()
def full(platform: str = typer.Option(..., help="Platform to enumerate (ibm, braket)"),
         output: str = typer.Option("full_report.json", help="Output JSON file"),
         hypotheses: int = typer.Option(10, help="Number of hypotheses to generate")):
         
    creds = get_credentials(platform)
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
         console.print("[red]Error:[/red] ANTHROPIC_API_KEY required for full scan with hypothesis generation.")
         raise typer.Exit(code=1)
         
    full_platform = "ibm-quantum" if platform == "ibm" else "amazon-braket"
         
    console.print(f"[bold]Starting Full Scan on {platform}[/bold]")
    
    # 1. Enum
    console.print("Running enumeration...")
    if platform == "ibm":
        enumerator_ibm_full = IBMQuantumEnumerator(creds["ibm_token"])
        enum_result = enumerator_ibm_full.enumerate()
    else:
        enumerator_braket_full = BraketEnumerator(creds["aws_access_key_id"], creds["aws_secret_access_key"])
        enum_result = enumerator_braket_full.enumerate()
    
    # 2. Auth Probes
    console.print("Running auth probes...")
    ts_prober = TokenScopeProber(full_platform, creds)
    auth_res = ts_prober.probe()
    
    # 3. QHypo
    console.print("Generating AI hypotheses...")
    agent = QHypoAgent(anthropic_key)
    hypo_report = agent.generate_hypotheses(
        attack_surface_map=enum_result,
        auth_probe_result=auth_res,
        hypothesis_count=hypotheses
    )
    
    final_report = {
        "enumeration": json.loads(enum_result.model_dump_json()),
        "auth_probes": json.loads(auth_res.model_dump_json()),
        "hypotheses": json.loads(hypo_report.model_dump_json())
    }
    
    with open(output, "w") as f:
        json.dump(final_report, f, indent=2)
        
    console.print(f"[green]Full scan complete![/green] Generated {hypo_report.hypothesis_count} hypotheses.")
    console.print(f"Results saved to [bold]{output}[/bold]")

@attck_app.command("list-techniques")
def list_techniques(platform: str = typer.Option(None, help="Filter by platform")):
    loader = QuantumATTCKLoader()
    
    if platform:
        full_plat = "ibm-quantum" if platform == "ibm" else platform
        techniques = loader.get_techniques_for_platform(full_plat)
    else:
        techniques = loader.techniques
        
    table = Table(title=f"Q-ATT&CK Techniques{' for ' + platform if platform else ''}")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Tactic", style="magenta")
    table.add_column("Severity")
    
    for t in techniques:
        sev_color = {
            "critical": "red",
            "high": "orange3", # Rich doesn't have plain orange sometimes
            "medium": "yellow",
            "low": "blue"
        }.get(t.severity.value, "white")
        table.add_row(t.id, t.name, t.tactic_id, f"[{sev_color}]{t.severity.value}[/{sev_color}]")
        
    console.print(table)

@attck_app.command("show")
def show_technique(technique: str = typer.Argument(..., help="Technique ID")):
    loader = QuantumATTCKLoader()
    tech = loader.get_technique(technique)
    
    if not tech:
        console.print(f"[red]Technique {technique} not found.[/red]")
        raise typer.Exit(code=1)
        
    console.print(f"[bold cyan]{tech.id}[/bold cyan]: [bold]{tech.name}[/bold]")
    console.print(f"Tactic: {tech.tactic_id}")
    console.print(f"Severity: [bold]{tech.severity.value}[/bold]")
    console.print(f"Platforms: {', '.join(tech.platforms)}\n")
    console.print(f"[bold]Description:[/bold]\n{tech.description}\n")
    
    console.print("[bold]Detection Hints:[/bold]")
    for h in tech.detection_hints:
        console.print(f"- {h}")
        
    console.print("\n[bold]Mitigation Hints:[/bold]")
    for h in tech.mitigation_hints:
        console.print(f"- {h}")

if __name__ == "__main__":
    app()
