from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markup import escape
from rich.text import Text
from typing import Any


console = Console()


class Formatter:
    no_color = False

    def print_header(self, text: str) -> None:
        console.print(Panel.fit(text, style="cyan", border_style="cyan"))

    def print_success(self, message: str) -> None:
        console.print(f"[green]{escape(message)}[/green]")

    def print_error(self, message: str) -> None:
        console.print(f"[red]{escape(message)}[/red]")

    def print_warning(self, message: str) -> None:
        console.print(f"[yellow]{escape(message)}[/yellow]")

    def print_info(self, message: str) -> None:
        console.print(f"[blue]{escape(message)}[/blue]")

    def print_scanner_results(self, result) -> None:
        table = Table(
            title="Port Scan Results", show_header=True, header_style="bold magenta"
        )
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Status", justify="center")
        table.add_column("Service", style="blue")
        table.add_column("Latency", justify="right")

        for port in result.ports:
            status = port.status
            status_style = (
                "green"
                if status == "open"
                else "red"
                if status == "closed"
                else "yellow"
            )
            table.add_row(
                str(port.port),
                f"[{status_style}]{status}[/{status_style}]",
                port.service or "",
                f"{port.latency:.3f}s",
            )
        console.print(table)

    def print_fuzzer_results(self, result) -> None:
        table = Table(
            title="Directory Fuzz Results",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("URL", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Size", justify="right", style="dim")

        for f in result.found:
            status_style = (
                "green"
                if f.status_code < 300
                else "yellow"
                if f.status_code < 400
                else "red"
            )
            table.add_row(
                f.url,
                f"[{status_style}]{f.status_code}[/{status_style}]",
                str(f.content_length),
            )

        console.print(table)
        console.print(f"Found {len(result.found)} directories")

    def print_headers_results(self, result) -> None:
        table = Table(
            title="Security Headers Analysis",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Header", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Risk", justify="center")

        missing = []
        for h in result.analysis:
            status_icon = "[green]✓[/green]" if h.present else "[red]✗[/red]"
            risk_style = (
                "red"
                if h.risk == "high"
                else "yellow"
                if h.risk == "medium"
                else "green"
            )
            table.add_row(
                h.header, status_icon, f"[{risk_style}]{h.risk}[/{risk_style}]"
            )
            if not h.present:
                missing.append(h.header)

        console.print(table)
        console.print(f"Score: {result.score}/100 (Grade: {result.grade})")
        if missing:
            console.print(f"Missing: {', '.join(missing)}")

    def print_sqli_results(self, result) -> None:
        if result.vulnerable:
            console.print(f"[red]VULNERABLE to SQL Injection![/red]")
            console.print(f"Payload: {result.payload}")
        else:
            console.print("[green]No SQL injection vulnerabilities found[/green]")

    def print_xss_results(self, result) -> None:
        if result.vulnerable:
            console.print(f"[red]VULNERABLE to XSS![/red]")
            console.print(f"Payload: {result.payload}")
        else:
            console.print("[green]No XSS vulnerabilities found[/green]")

    def print_subdomain_results(self, result) -> None:
        table = Table(
            title="Subdomain Enumeration", show_header=True, header_style="bold magenta"
        )
        table.add_column("Subdomain", style="cyan")
        table.add_column("Status", style="yellow")

        for s in result.subdomains:
            status = "responded" if getattr(s, "verified", False) else "discovered"
            table.add_row(getattr(s, "subdomain", ""), status)

        console.print(table)
        console.print(f"Found {len(result.subdomains)} subdomains")


def format_title(text: str, style: str = "bold cyan") -> Text:
    return Text(text, style=style)


def print_header(text: str) -> None:
    console.print(Panel.fit(text, style="cyan", border_style="cyan"))


def print_success(message: str) -> None:
    console.print(f"[green]{escape(message)}[/green]")


def print_error(message: str) -> None:
    console.print(f"[red]{escape(message)}[/red]")


def print_warning(message: str) -> None:
    console.print(f"[yellow]{escape(message)}[/yellow]")


def print_info(message: str) -> None:
    console.print(f"[blue]{escape(message)}[/blue]")


def format_ports_table(ports: list[dict]) -> Table:
    table = Table(
        title="Port Scan Results", show_header=True, header_style="bold magenta"
    )
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Service", style="blue")
    table.add_column("Latency", justify="right")

    for port in ports:
        status = port.get("status", "unknown")
        status_style = (
            "green" if status == "open" else "red" if status == "closed" else "yellow"
        )
        table.add_row(
            str(port.get("port", "")),
            f"[{status_style}]{status}[/{status_style}]",
            port.get("service", ""),
            f"{port.get('latency', 0):.3f}s",
        )

    return table


def format_directories_table(dirs: list[dict]) -> Table:
    table = Table(
        title="Directory Fuzz Results", show_header=True, header_style="bold magenta"
    )
    table.add_column("URL", style="cyan")
    table.add_column("Status", justify="center", style="blue")
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Redirect", style="dim")

    for d in dirs:
        status_style = (
            "green"
            if d.get("status_code", 0) < 300
            else "yellow"
            if d.get("status_code", 0) < 400
            else "red"
        )
        table.add_row(
            d.get("url", ""),
            f"[{status_style}]{d.get('status_code', '')}[/{status_style}]",
            str(d.get("content_length", 0)),
            d.get("redirect", "-"),
        )

    return table


def format_headers_table(headers: list[dict]) -> Table:
    table = Table(
        title="Security Headers Analysis", show_header=True, header_style="bold magenta"
    )
    table.add_column("Header", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Value", style="dim")
    table.add_column("Risk", justify="center")

    for h in headers:
        present = h.get("present", False)
        status_icon = "[green]✓[/green]" if present else "[red]✗[/red]"
        risk = h.get("risk", "low")
        risk_style = (
            "red" if risk == "high" else "yellow" if risk == "medium" else "green"
        )
        table.add_row(
            h.get("header", ""),
            status_icon,
            h.get("value", "-")[:50] if h.get("value") else "-",
            f"[{risk_style}]{risk}[/{risk_style}]",
        )

    return table


def format_vulns_table(vulns: list[dict], title: str = "Vulnerabilities") -> Table:
    table = Table(title=title, show_header=True, header_style="bold red")
    table.add_column("URL", style="cyan", no_wrap=False)
    table.add_column("Type", style="yellow")
    table.add_column("Evidence", style="dim", no_wrap=False)

    for v in vulns:
        table.add_row(
            v.get("url", "")[:60],
            v.get("type", ""),
            v.get("evidence", "")[:40],
        )

    return table


def format_subdomains_table(subdomains: list[dict]) -> Table:
    table = Table(
        title="Subdomain Enumeration", show_header=True, header_style="bold magenta"
    )
    table.add_column("Subdomain", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Value", style="dim")

    for s in subdomains:
        table.add_row(
            s.get("subdomain", ""),
            s.get("record_type", ""),
            s.get("value", ""),
        )

    return table


def format_score(score: int, grade: str) -> Panel:
    color = "green" if grade in ["A", "B"] else "yellow" if grade == "C" else "red"
    return Panel.fit(
        f"[{color}]{grade}[/{color}] ({score}/100)",
        title="Security Score",
        border_style=color,
    )


def print_json(data: Any) -> None:
    import json

    console.print_json(data)
