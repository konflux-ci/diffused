"""CLI tool to interact with Diffused."""

import json
import os
from typing import IO, Optional, Union, cast

import click
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from diffused.differ import VulnerabilityDiffer


def format_vulnerabilities_table(
    vulnerabilities_data: dict,
    file: Optional[IO[str]],
    title: str = "Fixed Vulnerability Differences",
    change_key: str = "removed",
    change_label: str = "Removed",
) -> None:
    """Format vulnerability data as a rich table."""
    console = Console(file=file)

    table = Table(title=title)
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Package", style="magenta")
    table.add_column("Previous Version", style="red")
    table.add_column("New Version", style="green")
    table.add_column("Status", style="yellow")

    for cve_id, packages in vulnerabilities_data.items():
        for package_info in packages:
            for package_name, details in package_info.items():
                status = change_label if details[change_key] else "Updated"
                table.add_row(
                    cve_id,
                    package_name,
                    details["previous_version"],
                    details["new_version"],
                    status,
                )

    console.print(table)


def format_vulnerabilities_list(
    vulnerabilities_list: list,
    file: Optional[IO[str]],
    label: str = "Fixed Vulnerabilities",
) -> None:
    """Format vulnerability list as a rich panel with columns."""

    console = Console(file=file)

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

    title = f"{label} ({len(vulnerabilities_list)} total)"
    console.print(Panel(columns, title=title, border_style="cyan", padding=(1, 1)))


# metadata describing how each vulnerability direction is rendered
_DIRECTIONS = {
    "fixed": {
        "list_label": "Fixed Vulnerabilities",
        "table_title": "Fixed Vulnerability Differences",
        "change_key": "removed",
        "change_label": "Removed",
    },
    "new": {
        "list_label": "New Vulnerabilities",
        "table_title": "New Vulnerability Differences",
        "change_key": "added",
        "change_label": "Added",
    },
}


def _get_data(differ: VulnerabilityDiffer, direction: str, all_info: bool) -> Union[list, dict]:
    """Return the vulnerability data for the given direction."""
    if direction == "fixed":
        return differ.vulnerabilities_diff_all_info if all_info else differ.vulnerabilities_diff
    return differ.new_vulnerabilities_all_info if all_info else differ.new_vulnerabilities


def _report(
    differ: VulnerabilityDiffer,
    show: str,
    output: str,
    all_info: bool,
    file: IO[str],
) -> None:
    """Render the requested vulnerability report(s) to the output file."""
    directions = ["fixed", "new"] if show == "all" else [show]

    if output == "json":
        if show == "all":
            combined = {d: _get_data(differ, d, all_info) for d in directions}
            json.dump(combined, file, indent=2)
        else:
            json.dump(_get_data(differ, directions[0], all_info), file, indent=2)
        return

    # rich format
    for direction in directions:
        meta = _DIRECTIONS[direction]
        data = _get_data(differ, direction, all_info)
        if all_info:
            format_vulnerabilities_table(
                cast(dict, data),
                file,
                title=meta["table_title"],
                change_key=meta["change_key"],
                change_label=meta["change_label"],
            )
        else:
            format_vulnerabilities_list(cast(list, data), file, label=meta["list_label"])


# general command configs
@click.group(invoke_without_command=True)
@click.option(
    "-s",
    "--scanner",
    type=click.Choice(["acs", "grype", "trivy"], case_sensitive=False),
    default="trivy",
    help="Scanner to use for vulnerability detection (default=trivy).",
    required=False,
)
@click.pass_context
def cli(ctx: click.core.Context, scanner: str) -> None:
    """A CLI tool to interact with Diffused."""
    # Store scanner in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["scanner"] = scanner

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
    "--show",
    type=click.Choice(["fixed", "new", "all"], case_sensitive=False),
    default="fixed",
    help="Which vulnerabilities to report (fixed, new, or all).",
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
@click.option(
    "-f",
    "--file",
    type=click.File("w", lazy=True),
    default="-",
    help="File to write the output to.",
    required=False,
)
@click.pass_context
def sbom_diff(
    ctx: click.core.Context,
    previous_sbom: str,
    next_sbom: str,
    all_info: bool,
    show: str,
    output: str,
    file: IO[str],
):
    """Show the vulnerability diff between two SBOMs."""
    scanner = ctx.obj["scanner"]

    # ACS does not support SBOM scanning
    if scanner == "acs":
        click.echo("Error: SBOM scanning is not supported by the 'acs' scanner")
        exit(1)

    if not os.path.isfile(previous_sbom):
        click.echo(f"Could not find {previous_sbom}")
        exit(1)
    if not os.path.isfile(next_sbom):
        click.echo(f"Could not find {next_sbom}")
        exit(1)

    vuln_differ = VulnerabilityDiffer(
        previous_sbom=previous_sbom, next_sbom=next_sbom, scanner=scanner, scan_type="sbom"
    )

    try:
        _report(vuln_differ, show, output, all_info, file)
    except RuntimeError as e:
        click.echo(f"Error: {e}", err=True)
        exit(1)


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
    "--show",
    type=click.Choice(["fixed", "new", "all"], case_sensitive=False),
    default="fixed",
    help="Which vulnerabilities to report (fixed, new, or all).",
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
@click.option(
    "-f",
    "--file",
    type=click.File("w", lazy=True),
    default="-",
    help="File to write the output to.",
    required=False,
)
@click.pass_context
def image_diff(
    ctx: click.core.Context,
    previous_image: str,
    next_image: str,
    show: str,
    output: str,
    file: IO[str],
):
    """Show the vulnerability diff between two container images."""
    scanner = ctx.obj["scanner"]

    if os.path.isfile(previous_image) or os.path.isfile(next_image):
        click.echo(
            "image-diff: The 'previous-image' or 'next-image' option seems to be a file. Please "
            "provide a valid container image URL or use the sbom-diff command for SBOM files."
        )
        exit(1)

    vuln_differ = VulnerabilityDiffer(
        previous_image=previous_image, next_image=next_image, scanner=scanner, scan_type="image"
    )

    try:
        _report(vuln_differ, show, output, all_info=False, file=file)
    except RuntimeError as e:
        click.echo(f"Error: {e}", err=True)
        exit(1)


if __name__ == "__main__":
    cli()  # pragma: no cover
