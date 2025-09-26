"""Unit tests for CLI module."""

import json
import sys
from unittest.mock import MagicMock, patch

# Mock the diffused module before importing the CLI
sys.modules["diffused"] = MagicMock()
sys.modules["diffused.differ"] = MagicMock()

from diffusedcli.cli import cli, format_vulnerabilities_list, format_vulnerabilities_table


def test_cli_no_command(runner):
    """Test CLI with no command shows help."""
    result = runner.invoke(cli)
    assert result.exit_code == 0
    assert "A CLI tool to interact with Diffused" in result.output


@patch("diffusedcli.cli.os.path.isfile")
@patch("diffusedcli.cli.VulnerabilityDiffer")
@patch("diffusedcli.cli.format_vulnerabilities_list")
def test_sbom_diff_basic(
    mock_format_list,
    mock_differ,
    mock_isfile,
    runner,
    sample_vulnerabilities_list,
    test_previous_sbom_path,
    test_next_sbom_path,
):
    """Test basic sbom_diff command."""
    # setup mocks
    mock_isfile.return_value = True
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff = sample_vulnerabilities_list
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path]
    )

    assert result.exit_code == 0
    mock_isfile.assert_any_call(test_previous_sbom_path)
    mock_isfile.assert_any_call(test_next_sbom_path)
    mock_differ.assert_called_once_with(
        previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path, scanner="trivy"
    )
    # check that format_vulnerabilities_list was called with data and a file object
    assert mock_format_list.call_count == 1
    args, kwargs = mock_format_list.call_args
    assert args[0] == sample_vulnerabilities_list
    assert hasattr(args[1], "write")  # file-like object


@patch("diffusedcli.cli.os.path.isfile")
@patch("diffusedcli.cli.VulnerabilityDiffer")
@patch("diffusedcli.cli.format_vulnerabilities_table")
def test_sbom_diff_all_info(
    mock_format_table,
    mock_differ,
    mock_isfile,
    runner,
    sample_vulnerabilities_all_info,
    test_previous_sbom_path,
    test_next_sbom_path,
):
    """Test sbom_diff command with all info flag."""
    # setup mocks
    mock_isfile.return_value = True
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff_all_info = sample_vulnerabilities_all_info
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path, "-a"]
    )

    assert result.exit_code == 0
    # check that format_vulnerabilities_table was called with data and a file object
    assert mock_format_table.call_count == 1
    args, kwargs = mock_format_table.call_args
    assert args[0] == sample_vulnerabilities_all_info
    assert hasattr(args[1], "write")  # file-like object


@patch("diffusedcli.cli.os.path.isfile")
@patch("diffusedcli.cli.VulnerabilityDiffer")
def test_sbom_diff_json_output(
    mock_differ,
    mock_isfile,
    runner,
    sample_vulnerabilities_list,
    test_previous_sbom_path,
    test_next_sbom_path,
):
    """Test sbom_diff command with JSON output."""
    # setup mocks
    mock_isfile.return_value = True
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff = sample_vulnerabilities_list
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path, "-o", "json"]
    )

    assert result.exit_code == 0
    # verify JSON output
    output_data = json.loads(result.output.strip())
    assert output_data == sample_vulnerabilities_list


@patch("diffusedcli.cli.os.path.isfile")
@patch("diffusedcli.cli.VulnerabilityDiffer")
def test_sbom_diff_json_all_info(
    mock_differ,
    mock_isfile,
    runner,
    sample_vulnerabilities_all_info,
    test_previous_sbom_path,
    test_next_sbom_path,
):
    """Test sbom_diff command with JSON output and all info."""
    # setup mocks
    mock_isfile.return_value = True
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff_all_info = sample_vulnerabilities_all_info
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli,
        ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path, "-a", "-o", "json"],
    )

    assert result.exit_code == 0
    # verify JSON output
    output_data = json.loads(result.output.strip())
    assert output_data == sample_vulnerabilities_all_info


@patch("diffusedcli.cli.os.path.isfile")
def test_sbom_diff_file_not_found_previous(
    mock_isfile, runner, test_previous_sbom_path, test_next_sbom_path
):
    """Test sbom_diff with non-existent previous file."""
    mock_isfile.side_effect = lambda path: path != test_previous_sbom_path

    result = runner.invoke(
        cli, ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path]
    )

    assert result.exit_code == 1
    assert f"Could not find {test_previous_sbom_path}" in result.output


@patch("diffusedcli.cli.os.path.isfile")
def test_sbom_diff_file_not_found_next(
    mock_isfile, runner, test_previous_sbom_path, test_next_sbom_path
):
    """Test sbom_diff with non-existent next file."""
    mock_isfile.side_effect = lambda path: path != test_next_sbom_path

    result = runner.invoke(
        cli, ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path]
    )

    assert result.exit_code == 1
    assert f"Could not find {test_next_sbom_path}" in result.output


@patch("diffusedcli.cli.VulnerabilityDiffer")
@patch("diffusedcli.cli.format_vulnerabilities_list")
def test_image_diff_basic(
    mock_format_list,
    mock_differ,
    runner,
    sample_vulnerabilities_list,
    test_previous_image,
    test_next_image,
):
    """Test basic image_diff command."""
    # setup mocks
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff = sample_vulnerabilities_list
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(cli, ["image-diff", "-p", test_previous_image, "-n", test_next_image])

    assert result.exit_code == 0
    mock_differ.assert_called_once_with(
        previous_image=test_previous_image, next_image=test_next_image, scanner="trivy"
    )
    # check that format_vulnerabilities_list was called with data and a file object
    assert mock_format_list.call_count == 1
    args, kwargs = mock_format_list.call_args
    assert args[0] == sample_vulnerabilities_list
    assert hasattr(args[1], "write")  # file-like object


@patch("diffusedcli.cli.VulnerabilityDiffer")
@patch("diffusedcli.cli.format_vulnerabilities_table")
def test_image_diff_all_info(
    mock_format_table,
    mock_differ,
    runner,
    sample_vulnerabilities_all_info,
    test_previous_image,
    test_next_image,
):
    """Test image_diff command with all info flag."""
    # setup mocks
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff_all_info = sample_vulnerabilities_all_info
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["image-diff", "-p", test_previous_image, "-n", test_next_image, "-a"]
    )

    assert result.exit_code == 0
    # check that format_vulnerabilities_table was called with data and a file object
    assert mock_format_table.call_count == 1
    args, kwargs = mock_format_table.call_args
    assert args[0] == sample_vulnerabilities_all_info
    assert hasattr(args[1], "write")  # file-like object


@patch("diffusedcli.cli.VulnerabilityDiffer")
def test_image_diff_json_output(
    mock_differ, runner, sample_vulnerabilities_list, test_previous_image, test_next_image
):
    """Test image_diff command with JSON output."""
    # setup mocks
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff = sample_vulnerabilities_list
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["image-diff", "-p", test_previous_image, "-n", test_next_image, "-o", "json"]
    )

    assert result.exit_code == 0
    # verify JSON output
    output_data = json.loads(result.output.strip())
    assert output_data == sample_vulnerabilities_list


@patch("diffusedcli.cli.VulnerabilityDiffer")
def test_image_diff_json_all_info(
    mock_differ, runner, sample_vulnerabilities_all_info, test_previous_image, test_next_image
):
    """Test image_diff command with JSON output and all info."""
    # setup mocks
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff_all_info = sample_vulnerabilities_all_info
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["image-diff", "-p", test_previous_image, "-n", test_next_image, "-a", "-o", "json"]
    )

    assert result.exit_code == 0
    # verify JSON output
    output_data = json.loads(result.output.strip())
    assert output_data == sample_vulnerabilities_all_info


def test_sbom_diff_missing_required_options(runner):
    """Test sbom_diff with missing required options."""
    result = runner.invoke(cli, ["sbom-diff"])
    assert result.exit_code != 0
    assert "Missing option" in result.output


def test_image_diff_missing_required_options(runner):
    """Test image_diff with missing required options."""
    result = runner.invoke(cli, ["image-diff"])
    assert result.exit_code != 0
    assert "Missing option" in result.output


@patch("diffusedcli.cli.os.path.isfile")
def test_image_diff_previous_image_is_file(mock_isfile, runner, test_next_image):
    """Test image_diff when previous image argument is a file path."""
    mock_isfile.side_effect = lambda path: path == "prev.json"

    result = runner.invoke(cli, ["image-diff", "-p", "prev.json", "-n", test_next_image])

    assert result.exit_code == 1
    assert "seems to be a file" in result.output
    assert "Please provide a valid container image URL" in result.output


@patch("diffusedcli.cli.os.path.isfile")
def test_image_diff_next_image_is_file(mock_isfile, runner, test_previous_image):
    """Test image_diff when next image argument is a file path."""
    mock_isfile.side_effect = lambda path: path == "next.json"

    result = runner.invoke(cli, ["image-diff", "-p", test_previous_image, "-n", "next.json"])

    assert result.exit_code == 1
    assert "seems to be a file" in result.output
    assert "Please provide a valid container image URL" in result.output


@patch("diffusedcli.cli.os.path.isfile")
def test_image_diff_both_images_are_files(mock_isfile, runner):
    """Test image_diff when both image arguments are file paths."""
    mock_isfile.return_value = True

    result = runner.invoke(cli, ["image-diff", "-p", "prev.json", "-n", "next.json"])

    assert result.exit_code == 1
    assert "seems to be a file" in result.output
    assert "use the sbom-diff command for SBOM files" in result.output


def test_invalid_output_format(runner, test_previous_sbom_path, test_next_sbom_path):
    """Test CLI with invalid output format."""
    result = runner.invoke(
        cli,
        ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path, "-o", "invalid"],
    )
    assert result.exit_code != 0
    assert "Invalid value" in result.output


@patch("diffusedcli.cli.Console")
def test_format_vulnerabilities_list_empty(mock_console):
    """Test format_vulnerabilities_list with empty list."""
    mock_console_instance = MagicMock()
    mock_console.return_value = mock_console_instance

    format_vulnerabilities_list([], None)

    mock_console_instance.print.assert_called_once()
    # verify it was called with a Panel for no vulnerabilities
    call_args = mock_console_instance.print.call_args[0][0]
    assert hasattr(call_args, "renderable")  # Panel object


@patch("diffusedcli.cli.Console")
@patch("diffusedcli.cli.Panel")
@patch("diffusedcli.cli.Columns")
@patch("diffusedcli.cli.Text")
def test_format_vulnerabilities_list_with_data(
    mock_text, mock_columns, mock_panel, mock_console, sample_vulnerabilities_list
):
    """Test format_vulnerabilities_list with data."""
    mock_console_instance = MagicMock()
    mock_console.return_value = mock_console_instance

    format_vulnerabilities_list(sample_vulnerabilities_list, None)

    # verify Text objects were created for each CVE
    assert mock_text.call_count == len(sample_vulnerabilities_list)
    mock_console_instance.print.assert_called_once()


@patch("diffusedcli.cli.Console")
@patch("diffusedcli.cli.Table")
def test_format_vulnerabilities_table(mock_table, mock_console, sample_vulnerabilities_all_info):
    """Test format_vulnerabilities_table function."""
    mock_console_instance = MagicMock()
    mock_console.return_value = mock_console_instance
    mock_table_instance = MagicMock()
    mock_table.return_value = mock_table_instance

    format_vulnerabilities_table(sample_vulnerabilities_all_info, None)

    # verify table was created and configured
    mock_table.assert_called_once_with(title="Vulnerability Differences")
    assert mock_table_instance.add_column.call_count == 5  # 5 columns
    assert mock_table_instance.add_row.call_count == 2  # 2 packages in test data
    mock_console_instance.print.assert_called_once_with(mock_table_instance)


def test_sbom_diff_case_insensitive_output(runner, test_previous_sbom_path, test_next_sbom_path):
    """Test that output format option is case insensitive."""
    with (
        patch("diffusedcli.cli.os.path.isfile", return_value=True),
        patch("diffusedcli.cli.VulnerabilityDiffer") as mock_differ,
    ):

        mock_differ_instance = MagicMock()
        mock_differ_instance.vulnerabilities_diff = ["CVE-2024-1234"]
        mock_differ.return_value = mock_differ_instance

        # test uppercase JSON
        result = runner.invoke(
            cli,
            ["sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path, "-o", "JSON"],
        )

        assert result.exit_code == 0
        output_data = json.loads(result.output.strip())
        assert output_data == ["CVE-2024-1234"]


def test_sbom_diff_with_trivy_scanner(
    runner, sample_vulnerabilities_list, test_previous_sbom_path, test_next_sbom_path
):
    """Test sbom-diff command with trivy scanner (explicit)."""
    with (
        patch("diffusedcli.cli.os.path.isfile", return_value=True),
        patch("diffusedcli.cli.VulnerabilityDiffer") as mock_differ,
    ):
        mock_differ_instance = MagicMock()
        mock_differ_instance.vulnerabilities_diff = sample_vulnerabilities_list
        mock_differ.return_value = mock_differ_instance

        result = runner.invoke(
            cli,
            [
                "--scanner",
                "trivy",
                "sbom-diff",
                "-p",
                test_previous_sbom_path,
                "-n",
                test_next_sbom_path,
            ],
        )

        assert result.exit_code == 0
        mock_differ.assert_called_once_with(
            previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path, scanner="trivy"
        )


def test_sbom_diff_with_acs_scanner_error(runner, test_previous_sbom_path, test_next_sbom_path):
    """Test sbom-diff command fails when ACS scanner is used."""
    result = runner.invoke(
        cli,
        ["--scanner", "acs", "sbom-diff", "-p", test_previous_sbom_path, "-n", test_next_sbom_path],
    )

    assert result.exit_code == 1
    assert "Error: Only 'trivy' scanner is supported for SBOM scanning, got 'acs'" in result.output


def test_sbom_diff_scanner_case_insensitive(runner, test_previous_sbom_path, test_next_sbom_path):
    """Test that scanner option is case insensitive for sbom-diff."""
    with (
        patch("diffusedcli.cli.os.path.isfile", return_value=True),
        patch("diffusedcli.cli.VulnerabilityDiffer") as mock_differ,
    ):
        mock_differ_instance = MagicMock()
        mock_differ_instance.vulnerabilities_diff = ["CVE-2024-1234"]
        mock_differ.return_value = mock_differ_instance

        # test uppercase TRIVY
        result = runner.invoke(
            cli,
            [
                "--scanner",
                "TRIVY",
                "sbom-diff",
                "-p",
                test_previous_sbom_path,
                "-n",
                test_next_sbom_path,
            ],
        )

        assert result.exit_code == 0
        mock_differ.assert_called_once_with(
            previous_sbom=test_previous_sbom_path, next_sbom=test_next_sbom_path, scanner="trivy"
        )


def test_cli_help_commands(runner):
    """Test help for individual commands."""
    # test sbom-diff help
    result = runner.invoke(cli, ["sbom-diff", "--help"])
    assert result.exit_code == 0
    assert "Show the vulnerability diff between two SBOMs" in result.output

    # test image-diff help
    result = runner.invoke(cli, ["image-diff", "--help"])
    assert result.exit_code == 0
    assert "Show the vulnerability diff between two container images" in result.output


@patch("diffusedcli.cli.VulnerabilityDiffer")
def test_integration_all_options(mock_differ, runner, test_previous_sbom_path, test_next_sbom_path):
    """Test commands with all options combined."""
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff_all_info = {"CVE-2024-1234": []}
    mock_differ.return_value = mock_differ_instance

    with patch("diffusedcli.cli.os.path.isfile", return_value=True):
        result = runner.invoke(
            cli,
            [
                "sbom-diff",
                "--previous-sbom",
                test_previous_sbom_path,
                "--next-sbom",
                test_next_sbom_path,
                "--all-info",
                "--output",
                "json",
            ],
        )

    assert result.exit_code == 0
    output_data = json.loads(result.output.strip())
    assert output_data == {"CVE-2024-1234": []}


@patch("diffusedcli.cli.VulnerabilityDiffer")
def test_image_diff_with_acs_scanner(
    mock_differ, runner, sample_vulnerabilities_list, test_previous_image, test_next_image
):
    """Test image_diff command with ACS scanner."""
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff = sample_vulnerabilities_list
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["--scanner", "acs", "image-diff", "-p", test_previous_image, "-n", test_next_image]
    )

    assert result.exit_code == 0
    mock_differ.assert_called_once_with(
        previous_image=test_previous_image, next_image=test_next_image, scanner="acs"
    )


@patch("diffusedcli.cli.VulnerabilityDiffer")
def test_image_diff_with_trivy_scanner(
    mock_differ, runner, sample_vulnerabilities_list, test_previous_image, test_next_image
):
    """Test image_diff command with Trivy scanner (explicit)."""
    mock_differ_instance = MagicMock()
    mock_differ_instance.vulnerabilities_diff = sample_vulnerabilities_list
    mock_differ.return_value = mock_differ_instance

    result = runner.invoke(
        cli, ["--scanner", "trivy", "image-diff", "-p", test_previous_image, "-n", test_next_image]
    )

    assert result.exit_code == 0
    mock_differ.assert_called_once_with(
        previous_image=test_previous_image, next_image=test_next_image, scanner="trivy"
    )


def test_image_diff_invalid_scanner(runner, test_previous_image, test_next_image):
    """Test image_diff command with invalid scanner."""
    result = runner.invoke(
        cli,
        ["--scanner", "invalid", "image-diff", "-p", test_previous_image, "-n", test_next_image],
    )

    assert result.exit_code != 0
    assert "Invalid value" in result.output
    assert "invalid" in result.output
    assert "trivy" in result.output
    assert "acs" in result.output


def test_image_diff_scanner_case_insensitive(runner, test_previous_image, test_next_image):
    """Test that scanner option is case insensitive."""
    with patch("diffusedcli.cli.VulnerabilityDiffer") as mock_differ:
        mock_differ_instance = MagicMock()
        mock_differ_instance.vulnerabilities_diff = ["CVE-2024-1234"]
        mock_differ.return_value = mock_differ_instance

        # test uppercase ACS
        result = runner.invoke(
            cli,
            ["--scanner", "ACS", "image-diff", "-p", test_previous_image, "-n", test_next_image],
        )

        assert result.exit_code == 0
        mock_differ.assert_called_once_with(
            previous_image=test_previous_image, next_image=test_next_image, scanner="acs"
        )


# the following test throws the following warning on pytest:
# src/tests/test_cli.py::test_main_execution
#  <frozen runpy>:128: RuntimeWarning: 'diffused.cli' found in sys.modules after
#  import of package 'diffused', but prior to execution of 'diffused.cli'; this
#  may result in unpredictable behaviour
#
# -- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
#
# As it is tricky to test the if __name__ == '__main__' block on unit tests, we
# are disabling the test and setting the line to # pragma: no cover.
#
# def test_main_execution():
#     """Test the if __name__ == '__main__' block by running module as script."""
#     import runpy
#     import sys
#     from io import StringIO
#     from unittest.mock import patch
#
#     # capture stdout to verify the help message is displayed
#     captured_output = StringIO()
#
#     with (
#         patch("sys.stdout", captured_output),
#         patch("sys.argv", ["diffused.cli"]),
#     ):  # simulate no arguments
#         try:
#             runpy.run_module("diffused.cli", run_name="__main__")
#         except SystemExit:
#             # click calls sys.exit(), which is expected
#             pass
#
#     # verify help text was displayed
#     output = captured_output.getvalue()
#     assert "A CLI tool to interact with Diffused" in output
