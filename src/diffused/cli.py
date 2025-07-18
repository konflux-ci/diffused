"""CLI tool to interact with Diffused."""

import json
import os

import click
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from diffused.differ import VulnerabilityDiffer


def format_vulnerabilities_table(vulnerabilities_data: dict) -> None:
    """Format vulnerability data as a rich table."""
    console = Console()

    table = Table(title="Vulnerability Differences")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Package", style="magenta")
    table.add_column("Previous Version", style="red")
    table.add_column("New Version", style="green")
    table.add_column("Status", style="yellow")

    for cve_id, packages in vulnerabilities_data.items():
        for package_info in packages:
            for package_name, details in package_info.items():
                status = "Removed" if details["removed"] else "Updated"
                table.add_row(
                    cve_id,
                    package_name,
                    details["previous_version"],
                    details["new_version"],
                    status,
                )

    console.print(table)


def format_vulnerabilities_list(vulnerabilities_list: list) -> None:
    """Format vulnerability list as a rich panel with columns."""
    console = Console()

    if not vulnerabilities_list:
        console.print(
            Panel("No vulnerabilities found", title="Vulnerability Summary", border_style="green")
        )
        return

    # create styled CVE items
    cve_items = []
    for cve in vulnerabilities_list:
        cve_text = Text(cve, style="bold red")
        cve_items.append(Panel(cve_text, width=20, padding=(0, 1)))

    # display in columns for better layout
    columns = Columns(cve_items, equal=True, expand=True)

    title = f"Fixed Vulnerabilities ({len(vulnerabilities_list)} total)"
    console.print(Panel(columns, title=title, border_style="cyan", padding=(1, 1)))


# general command configs
@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.core.Context) -> None:
    """A CLI tool to interact with Diffused."""
    # if no subcommand is invoked, display help and exit
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        return


# sbom vulnerability diff command
@cli.command()
@click.option(
    "-p",
    "--previous-sbom",
    metavar="file",
    help="SBOM from the previous container image.",
    required=True,
)
@click.option(
    "-n",
    "--next-sbom",
    metavar="file",
    help="SBOM from the next container image.",
    required=True,
)
@click.option(
    "-a",
    "--all-info",
    is_flag=True,
    help="Outputs all information for each vulnerability.",
    required=False,
)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["rich", "json"], case_sensitive=False),
    default="rich",
    help="Output format (rich or json).",
    required=False,
)
def sbom_diff(previous_sbom: str, next_sbom: str, all_info: bool, output: str):
    """Show the vulnerability diff between two SBOMs."""
    if not os.path.isfile(previous_sbom):
        click.echo(f"Could not find {previous_sbom}")
        exit(1)
    if not os.path.isfile(next_sbom):
        click.echo(f"Could not find {next_sbom}")
        exit(1)

    vuln_differ = VulnerabilityDiffer(previous_sbom=previous_sbom, next_sbom=next_sbom)

    if output == "json":
        if not all_info:
            click.echo(json.dumps(vuln_differ.vulnerabilities_diff, indent=2))
        else:
            click.echo(json.dumps(vuln_differ.vulnerabilities_diff_all_info, indent=2))
    else:  # rich format
        if not all_info:
            format_vulnerabilities_list(vuln_differ.vulnerabilities_diff)
        else:
            format_vulnerabilities_table(vuln_differ.vulnerabilities_diff_all_info)


# image vulnerability diff command
@cli.command()
@click.option(
    "-p",
    "--previous-image",
    metavar="str",
    help="URL from the previous container image.",
    required=True,
)
@click.option(
    "-n",
    "--next-image",
    metavar="str",
    help="URL from the next container image.",
    required=True,
)
@click.option(
    "-a",
    "--all-info",
    is_flag=True,
    help="Outputs all information for each vulnerability.",
    required=False,
)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["rich", "json"], case_sensitive=False),
    default="rich",
    help="Output format (rich or json).",
    required=False,
)
def image_diff(previous_image: str, next_image: str, all_info: bool, output: str):
    """Show the vulnerability diff between two container images."""
    if os.path.isfile(previous_image) or os.path.isfile(next_image):
        click.echo(
            "image-diff: The 'previous-image' or 'next-image' option seems to be a file. Please "
            "provide a valid container image URL or use the sbom-diff command for SBOM files."
        )
        exit(1)

    vuln_differ = VulnerabilityDiffer(previous_image=previous_image, next_image=next_image)

    if output == "json":
        if not all_info:
            click.echo(json.dumps(vuln_differ.vulnerabilities_diff, indent=2))
        else:
            click.echo(json.dumps(vuln_differ.vulnerabilities_diff_all_info, indent=2))
    else:  # rich format
        if not all_info:
            format_vulnerabilities_list(vuln_differ.vulnerabilities_diff)
        else:
            format_vulnerabilities_table(vuln_differ.vulnerabilities_diff_all_info)


if __name__ == "__main__":
    cli()  # pragma: no cover
