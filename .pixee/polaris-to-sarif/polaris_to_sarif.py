#!/usr/bin/env python3
"""
Generate SARIF output from Polaris findings API and optionally upload to Pixee

Outputs to: polaris-sast-results-<timestamp>.sarif.json

Usage:
    # Generate SARIF only:
    python3 polaris_to_sarif.py --project-id <project_id> --portfolio-id <portfolio_id> --polaris-api-token <token> [--polaris-branch-name <branch>] [--test-id latest]

    # Generate SARIF and upload to Pixee:
    python3 polaris_to_sarif.py --project-id <project_id> --portfolio-id <portfolio_id> --polaris-api-token <token> --polaris-branch-name <polaris_branch> --pixee-api-key <key> --pixee-repository-id <pixee_repo_id> --pixee-branch-name <scm_branch>

Branch Parameters:
    --polaris-branch-name: The branch name in Polaris to filter issues from. This is the branch
                           where scan results are stored in Polaris (e.g., a long-lived release branch).

    --pixee-branch-name:   The branch name to send to Pixee for SCM lookup. This should be the
                           actual branch in your source control system (e.g., a feature branch).
                           Required when uploading to Pixee.

    Note: These can be different when customers upload feature branch results to a long-lived
    release branch in Polaris. The Polaris branch is used for filtering, while the Pixee branch
    is used to locate the code in your SCM.
"""

import json
import os
import sys
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path

import requests
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_sleep_log
import logging

# Configure logging for tenacity
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Rich console for pretty output
console = Console()
app = typer.Typer(help="Convert Black Duck Polaris security findings to SARIF format")


def create_session(proxy_url: Optional[str] = None, no_proxy: bool = False) -> requests.Session:
    """
    Create a requests session with optional proxy configuration.

    Args:
        proxy_url: Explicit proxy URL (e.g., "http://proxy.example.com:8080")
        no_proxy: If True, disable proxy even if environment variables are set

    Returns:
        Configured requests Session
    """
    session = requests.Session()

    if no_proxy:
        # Explicitly disable proxy
        session.trust_env = False
        session.proxies = {}
    elif proxy_url:
        # Use explicit proxy
        session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
    # else: default (trust_env=True) - respects HTTP_PROXY/HTTPS_PROXY

    return session


# Retry decorator for Polaris API calls
polaris_retry = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=10, max=60),
    retry=retry_if_exception_type((requests.exceptions.RequestException,)),
    before_sleep=before_sleep_log(logger, logging.INFO),
    reraise=True
)

# Retry decorator for Pixee API calls — retries on connection/SSL errors, not HTTP errors
pixee_retry = retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=5, max=30),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    before_sleep=before_sleep_log(logger, logging.INFO),
    reraise=True
)


@polaris_retry
def get_branch_id(portfolio_id: str, project_id: str, branch_name: str, api_token: str, base_url: str = "https://polaris.blackduck.com", session: requests.Session = None) -> str:
    """Look up branch ID from branch name"""
    url = f"{base_url}/api/portfolios/{portfolio_id}/branches?_filter=(projectId=={project_id})"
    headers = {
        "accept": "application/vnd.polaris.portfolios.branches-1+json",
        "Api-token": api_token
    }

    if session is None:
        session = requests.Session()

    response = session.get(url, headers=headers)
    response.raise_for_status()

    data = response.json()
    branches = data.get("_items", [])

    for branch in branches:
        if branch.get("name") == branch_name:
            return branch.get("id")

    # Branch not found, list available branches
    available = [b.get("name") for b in branches]
    raise ValueError(f"Branch '{branch_name}' not found. Available branches: {', '.join(available)}")


def get_application_id(portfolio_id: str, project_id: str, api_token: str, base_url: str = "https://polaris.blackduck.com", session: requests.Session = None) -> Optional[str]:
    """Find the application (portfolio-item) ID that contains the given project."""
    if session is None:
        session = requests.Session()

    headers = {"Api-token": api_token}

    try:
        response = session.get(f"{base_url}/api/portfolios/{portfolio_id}/applications", headers=headers)
        response.raise_for_status()
        applications = response.json().get("_items", [])

        for app in applications:
            app_id = app.get("id")
            projects_response = session.get(
                f"{base_url}/api/portfolios/{portfolio_id}/applications/{app_id}/projects",
                headers=headers
            )
            if projects_response.ok:
                project_ids = [p.get("id") for p in projects_response.json().get("_items", [])]
                if project_id in project_ids:
                    return app_id
    except Exception as e:
        console.print(f"[yellow]Warning: Could not look up application ID: {e}[/yellow]")

    return None


def get_polaris_issues(project_id: str, api_token: str, test_id: str = "latest", base_url: str = "https://polaris.blackduck.com", branch_id: Optional[str] = None, session: requests.Session = None) -> List[Dict]:
    """Fetch issues from Polaris findings API with pagination support"""
    all_issues = []

    if session is None:
        session = requests.Session()

    # Build initial URL
    full_url = f"{base_url}/api/findings/issues?testId={test_id}&_first=100&_includeType=true&_includeOccurrenceProperties=true&_includeFirstDetectedOn=true&projectId={project_id}"

    # Add branch filter if specified
    if branch_id:
        full_url += f"&branchId={branch_id}"

    headers = {
        "accept": "application/vnd.polaris.findings.issues-1+json",
        "Api-token": api_token
    }

    # Fetch all pages with retry
    while full_url:
        @polaris_retry
        def _fetch_page(url):
            response = session.get(url, headers=headers)
            response.raise_for_status()
            return response.json()

        data = _fetch_page(full_url)
        items = data.get("_items", [])
        all_issues.extend(items)

        # Look for next page link
        next_url = None
        for link in data.get("_links", []):
            if link.get("rel") == "next":
                next_url = link.get("href")
                break

        full_url = next_url

    return all_issues


@polaris_retry
def get_occurrence_details(occurrence_url: str, api_token: str, session: requests.Session = None) -> Dict:
    """Fetch occurrence details including file paths"""
    headers = {
        "accept": "application/vnd.polaris.findings.occurrences-1+json",
        "Api-token": api_token
    }

    if session is None:
        session = requests.Session()

    response = session.get(occurrence_url, headers=headers)
    response.raise_for_status()
    return response.json()




def map_severity_to_level(severity: str) -> str:
    """Map Polaris severity to SARIF level"""
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note"
    }
    return severity_map.get(severity.lower(), "warning")


def calculate_security_severity(severity: str) -> str:
    """Calculate CVSS-like security severity score"""
    severity_scores = {
        "critical": "9.0",
        "high": "7.0",
        "medium": "5.0",
        "low": "3.0",
        "info": "1.0"
    }
    return severity_scores.get(severity.lower(), "5.0")


def extract_cwe_from_properties(props: Dict[str, str]) -> List[str]:
    """Extract CWE identifiers from issue properties"""
    cwes = []
    cwe_value = props.get("cwe", "")
    if cwe_value:
        # CWE can be like "CWE-20" or "CWE-20, CWE-79"
        for cwe in cwe_value.split(","):
            cwe = cwe.strip()
            if cwe.startswith("CWE-"):
                cwes.append(f"external/cwe/{cwe.lower()}")
    return cwes


def create_sarif_rule(issue: Dict, props: Dict[str, str]) -> Dict:
    """Create a SARIF rule from a Polaris issue"""
    issue_type = issue.get("type", {})
    localized = issue_type.get("_localized", {})
    issue_name = localized.get("name", "Unknown Issue")

    # Get descriptions
    description_detail = ""
    remediation = ""
    for detail in localized.get("otherDetails", []):
        if detail.get("key") == "description":
            description_detail = detail.get("value", "")
        elif detail.get("key") == "remediation":
            remediation = detail.get("value", "")

    # Build SAST rule ID: checker:kind|language (e.g., "hardcoded_credentials:password|java")
    checker = props.get("checker", "").lower()
    kind = props.get("kind", "").lower()
    language = props.get("language", "").lower().replace(" ", "_")

    if kind:
        rule_id = f"{checker}:{kind}|{language}"
    else:
        rule_id = f"{checker}|{language}"

    # Get severity
    severity = props.get("severity", "medium")

    # Build help text
    help_text = description_detail or props.get("description", issue_name)
    help_markdown = f"## Description\n{help_text}\n\n"

    if remediation:
        help_markdown += f"## Remediation\n{remediation}\n\n"

    # Extract CWE tags for SAST issues
    tags = ["security", "static_analysis"]
    cwes = extract_cwe_from_properties(props)
    tags.extend(cwes)

    rule = {
        "id": rule_id,
        "shortDescription": {
            "text": issue_name
        },
        "fullDescription": {
            "text": help_text
        },
        "defaultConfiguration": {
            "enabled": True,
            "level": map_severity_to_level(severity)
        },
        "help": {
            "text": help_text,
            "markdown": help_markdown
        },
        "properties": {
            "security-severity": calculate_security_severity(severity),
            "tags": tags
        }
    }

    return rule


def create_sarif_result(issue: Dict, props: Dict[str, str], occurrence: Dict = None, polaris_url: str = "https://polaris.blackduck.com", project_id: str = "", portfolio_id: str = "", app_id: str = "", branch_id: str = "") -> Dict:
    """Create a SARIF result from a Polaris SAST issue"""
    # Build SAST rule ID
    checker = props.get("checker", "").lower()
    kind = props.get("kind", "").lower()
    language = props.get("language", "").lower().replace(" ", "_")
    if kind:
        rule_id = f"{checker}:{kind}|{language}"
    else:
        rule_id = f"{checker}|{language}"

    issue_id = issue.get("id", "")

    # Get issue type name for the message
    issue_type = issue.get("type", {})
    localized = issue_type.get("_localized", {})
    issue_name = localized.get("name", "Security issue detected")

    # Get event description if available
    event_description = ""
    if occurrence and "main-event-description" in occurrence:
        event_description = occurrence["main-event-description"]
    elif "description" in props:
        event_description = props["description"]

    # Build Polaris link
    polaris_link = ""
    if project_id and issue_id:
        if portfolio_id and app_id and branch_id:
            polaris_link = (
                f"{polaris_url}/portfolio/portfolios/{portfolio_id}"
                f"/portfolio-items/{app_id}/projects/{project_id}"
                f"/issues/{issue_id}"
                f"?branchId={branch_id}&filter=occurrence%3Aissue-id%3D{issue_id}"
            )
        else:
            polaris_link = f"{polaris_url}/projects/{project_id}/issues/{issue_id}"

    # Create message with link and description
    message_parts = []
    if polaris_link:
        message_parts.append(f"[\\[See in Polaris\\]]({polaris_link})")
    if event_description:
        message_parts.append(event_description)
    elif issue_name:
        message_parts.append(issue_name)

    message_text = "\n\n".join(message_parts) if message_parts else "Security issue detected"

    # Build location from SAST issue properties
    locations = []

    # Get file path and line number from properties
    if "location" in props:
        file_path = props.get("location", "unknown")
        line_number = int(props.get("line-number", 1))

        locations.append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_path
                },
                "region": {
                    "startLine": line_number,
                    "startColumn": 1
                }
            }
        })

    # If no locations, create a default one
    if not locations:
        locations.append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "unknown"
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1
                }
            }
        })

    result = {
        "ruleId": rule_id,
        "message": {
            "text": message_text
        },
        "locations": locations,
        "guid": str(uuid.uuid4()),
        "partialFingerprints": {}
    }

    # Generate partial fingerprint hash
    if locations and "physicalLocation" in locations[0]:
        file_path = locations[0]["physicalLocation"]["artifactLocation"]["uri"]
        line_num = locations[0]["physicalLocation"]["region"]["startLine"]
        fingerprint_str = f"{rule_id}:{file_path}:{line_num}"
        fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        result["partialFingerprints"]["ruleIdLocationHash/v1"] = fingerprint_hash

    # Add code flows if we have event trace information
    if occurrence and "events" in occurrence:
        code_flows = []
        thread_flow_locations = []

        for event in occurrence["events"]:
            event_location = {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": event.get("filePath", file_path if locations else "unknown")
                        },
                        "region": {
                            "startLine": event.get("lineNumber", 1)
                        }
                    },
                    "message": {
                        "text": event.get("eventDescription", "")
                    }
                }
            }
            thread_flow_locations.append(event_location)

        if thread_flow_locations:
            code_flows.append({
                "threadFlows": [{
                    "locations": thread_flow_locations
                }]
            })
            result["codeFlows"] = code_flows

    return result


def convert_to_sarif(issues: List[Dict], api_token: str, project_id: str, test_id: str, base_url: str = "https://polaris.blackduck.com", session: requests.Session = None, portfolio_id: str = "", app_id: str = "", branch_id: str = "") -> Dict:
    """Convert Polaris issues to SARIF format (SAST only)"""
    rules = {}
    results = []

    if session is None:
        session = requests.Session()

    for issue in issues:
        # Extract properties
        props = {p["key"]: p["value"] for p in issue.get("occurrenceProperties", [])}

        # Filter: Only include SAST issues (ones with checker property)
        # Skip SCA issues (component vulnerabilities) which don't have source locations
        if "checker" not in props:
            continue

        # Build SAST rule ID from checker, kind, and language
        checker = props.get("checker", "").lower()
        kind = props.get("kind", "").lower()
        language = props.get("language", "").lower().replace(" ", "_")
        if kind:
            rule_id = f"{checker}:{kind}|{language}"
        else:
            rule_id = f"{checker}|{language}"

        if rule_id not in rules:
            rules[rule_id] = create_sarif_rule(issue, props)

        # Get occurrence details if available
        occurrence = None

        for link in issue.get("_links", []):
            if link.get("rel") == "occurrence":
                href = link.get("href", "")
                try:
                    occurrence = get_occurrence_details(href, api_token, session)
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not fetch occurrence details: {e}[/yellow]")

        # Create result
        result = create_sarif_result(issue, props, occurrence, project_id=project_id, portfolio_id=portfolio_id, app_id=app_id, branch_id=branch_id)
        results.append(result)

    # Log processing summary
    sast_issues = len(results)
    sca_filtered = len(issues) - sast_issues
    console.print(f"[green]✓[/green] Processed {sast_issues} SAST issues into SARIF (filtered out {sca_filtered} SCA issues)")

    # Build SARIF document
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Polaris",
                        "version": "2025.10.0",
                        "informationUri": "https://polaris.blackduck.com",
                        "rules": list(rules.values())
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat()
                    }
                ]
            }
        ]
    }

    return sarif


def get_polaris_integration_id(api_key: str, base_url: str = "https://edge.getpixee.com", session: requests.Session = None) -> Optional[str]:
    """Check if the polaris integration is configured and return its ID, or None if not found."""
    if session is None:
        session = requests.Session()

    headers = {
        'Authorization': f'Bearer {api_key}',
        'Accept': 'application/json',
    }
    url = f"{base_url}/api/v1/integrations?page-number=0&page-size=100"

    @pixee_retry
    def _fetch():
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    try:
        data = _fetch()
        items = data.get("_embedded", {}).get("items", [])
        for item in items:
            if item.get("id") == "polaris-default":
                return "polaris-default"
        return None
    except Exception as e:
        console.print(f"[yellow]Warning: Could not query integrations API after retries: {e}[/yellow]")
        return None


def upload_to_pixee(sarif_file: str, repository_id: str, api_key: str, branch_name: str = None, base_url: str = "https://edge.getpixee.com", session: requests.Session = None, trigger_analysis: bool = False, integration_id: Optional[str] = None) -> tuple:
    """
    Upload SARIF file to Pixee to create a new scan.
    Makes one or two API calls:
    1. POST /api/v1/repositories/{repository_id}/scans - creates scan with SARIF file
    2. POST /api/v1/scans/{scan_id}/analyses - triggers analysis processing (only if trigger_analysis=True)
    Returns tuple of (scan_id, analysis_id). analysis_id will be None if trigger_analysis=False.
    """
    if session is None:
        session = requests.Session()

    # Prepare metadata
    metadata = {"tool": "polaris"}
    if branch_name:
        metadata["branch"] = branch_name
    if integration_id:
        metadata["integration_id"] = integration_id

    # Prepare multipart upload (much simpler with requests!)
    url = f"{base_url}/api/v1/repositories/{repository_id}/scans"
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Accept': 'application/json'
    }

    # Read file into memory so the content can be re-sent on retry
    with open(sarif_file, 'rb') as f:
        file_content = f.read()
    filename = os.path.basename(sarif_file)

    @pixee_retry
    def _post_scan():
        files = {
            'metadata': (None, json.dumps(metadata), 'application/json'),
            'files': (filename, file_content, 'application/json')
        }
        response = session.post(url, headers=headers, files=files)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_body = e.response.text if e.response is not None else 'No error details'
            status_code = e.response.status_code if e.response is not None else 'Unknown'
            if not error_body:
                error_body = '(empty response body)'
            console.print(f"[red]HTTP Error Details:[/red]")
            console.print(f"  Status Code: {status_code}")
            console.print(f"  Response Body: {error_body[:2000]}")
            console.print(f"  Request URL: {url}")
            raise Exception(f"Failed to upload to Pixee: {status_code} - {error_body[:2000]}")
        return response.json()

    result = _post_scan()
    scan_id = result.get('id') or result.get('scanId')

    # Optionally trigger the analysis with a second API call
    if trigger_analysis:
        @pixee_retry
        def _post_analysis():
            analysis_response = session.post(f"{base_url}/api/v1/scans/{scan_id}/analyses", headers=headers)
            analysis_response.raise_for_status()
            return analysis_response.json()

        analysis_result = _post_analysis()
        analysis_id = analysis_result.get('id') or analysis_result.get('analysisId')
        return scan_id, analysis_id
    else:
        return scan_id, None


@app.command()
def main(
    # Required Polaris arguments (not required when --upload-sarif-file is used)
    project_id: Optional[str] = typer.Option(None, help="Polaris project ID"),
    portfolio_id: Optional[str] = typer.Option(None, help="Polaris portfolio ID"),
    polaris_api_token: Optional[str] = typer.Option(None, help="Polaris API token"),

    # Optional Polaris arguments
    test_id: str = typer.Option("latest", help="Test ID to query"),
    polaris_branch_name: Optional[str] = typer.Option(None, help="Branch name in Polaris to filter issues (e.g., long-lived release branch)"),
    base_url: str = typer.Option("https://polaris.blackduck.com", help="Polaris base URL"),

    # Proxy options
    proxy: Optional[str] = typer.Option(None, help="HTTP/HTTPS proxy URL (e.g., http://proxy.example.com:8080)"),
    no_proxy: bool = typer.Option(False, help="Disable proxy even if environment variables are set"),

    # Pixee upload options
    pixee_api_key: Optional[str] = typer.Option(None, help="Pixee API key (if provided, SARIF will be uploaded to Pixee)"),
    pixee_repository_id: Optional[str] = typer.Option(None, help="Pixee repository ID (required if uploading to Pixee)"),
    pixee_base_url: Optional[str] = typer.Option(None, help="Pixee base URL (required if uploading to Pixee)"),
    pixee_branch_name: Optional[str] = typer.Option(None, help="Branch name to send to Pixee for SCM lookup (e.g., feature branch). Required if uploading to Pixee."),
    trigger_analysis: bool = typer.Option(False, help="Automatically trigger analysis after uploading scan"),
    upload_sarif_file: Optional[str] = typer.Option(None, help="Skip Polaris fetch and upload an existing SARIF file directly to Pixee"),
):
    """Convert Black Duck Polaris SAST findings to SARIF format"""

    # Validate: must have either Polaris args or --upload-sarif-file
    if upload_sarif_file:
        if not Path(upload_sarif_file).exists():
            console.print(f"[red]Error:[/red] --upload-sarif-file '{upload_sarif_file}' does not exist")
            raise typer.Exit(1)
    else:
        if not project_id:
            console.print("[red]Error:[/red] --project-id is required (or use --upload-sarif-file to skip Polaris fetch)")
            raise typer.Exit(1)
        if not portfolio_id:
            console.print("[red]Error:[/red] --portfolio-id is required (or use --upload-sarif-file to skip Polaris fetch)")
            raise typer.Exit(1)
        if not polaris_api_token:
            console.print("[red]Error:[/red] --polaris-api-token is required (or use --upload-sarif-file to skip Polaris fetch)")
            raise typer.Exit(1)

    # Validate Pixee upload arguments
    if pixee_api_key:
        if not pixee_repository_id:
            console.print("[red]Error:[/red] --pixee-repository-id is required when --pixee-api-key is provided")
            raise typer.Exit(1)
        if not pixee_base_url:
            console.print("[red]Error:[/red] --pixee-base-url is required when --pixee-api-key is provided")
            raise typer.Exit(1)
        if not pixee_branch_name:
            console.print("[red]Error:[/red] --pixee-branch-name is required when --pixee-api-key is provided")
            console.print("[dim]Note: This is the branch in your SCM for Pixee to look up, which may differ from --polaris-branch-name[/dim]")
            raise typer.Exit(1)

    # Create session with proxy configuration
    session = create_session(proxy_url=proxy, no_proxy=no_proxy)

    try:
        if upload_sarif_file:
            output_filename = upload_sarif_file
            console.print(f"[cyan]Using existing SARIF file: [bold]{output_filename}[/bold][/cyan]")
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:

                # Look up branch ID from branch name if provided
                branch_id = None
                if polaris_branch_name:
                    task = progress.add_task(f"Looking up branch ID for '{polaris_branch_name}'...", total=None)
                    branch_id = get_branch_id(portfolio_id, project_id, polaris_branch_name, polaris_api_token, base_url, session)
                    progress.update(task, completed=True)
                    console.print(f"[green]✓[/green] Found branch ID: {branch_id}")

                # Look up application (portfolio-item) ID
                task = progress.add_task("Looking up application ID...", total=None)
                app_id = get_application_id(portfolio_id, project_id, polaris_api_token, base_url, session)
                progress.update(task, completed=True)
                if app_id:
                    console.print(f"[green]✓[/green] Found application ID: {app_id}")
                else:
                    console.print("[yellow]Warning: Could not determine application ID, Polaris links will use simplified format[/yellow]")

                # Fetch issues
                branch_info = f" (branch: {polaris_branch_name})" if polaris_branch_name else ""
                task = progress.add_task(f"Fetching issues from Polaris for project {project_id}{branch_info}...", total=None)
                issues = get_polaris_issues(project_id, polaris_api_token, test_id, base_url, branch_id, session)
                progress.update(task, completed=True)
                console.print(f"[green]✓[/green] Found {len(issues)} issues")

                # Convert to SARIF
                task = progress.add_task("Converting to SARIF format...", total=None)
                sarif = convert_to_sarif(issues, polaris_api_token, project_id, test_id, base_url, session, portfolio_id=portfolio_id, app_id=app_id or "", branch_id=branch_id or "")
                progress.update(task, completed=True)

            # Generate output filename with timestamp
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")
            output_filename = f"polaris-sast-results-{timestamp}.sarif.json"

            # Write SARIF file
            with open(output_filename, "w") as f:
                json.dump(sarif, f, indent=2)

            console.print(f"\n[green]✓[/green] Successfully generated SARIF file: [bold]{output_filename}[/bold]")
            console.print(f"  Total rules: {len(sarif['runs'][0]['tool']['driver']['rules'])}")
            console.print(f"  Total results: {len(sarif['runs'][0]['results'])}")

        # Upload to Pixee if API key provided
        if pixee_api_key:
            integration_id = get_polaris_integration_id(pixee_api_key, pixee_base_url, session)
            if integration_id:
                console.print(f"[dim]  Polaris integration detected: {integration_id}[/dim]")
            else:
                console.print(f"[dim]  No Polaris integration configured, uploading without integration_id[/dim]")

            console.print(f"\n[cyan]Uploading SARIF to Pixee repository {pixee_repository_id}...[/cyan]")
            console.print(f"[dim]  Using branch '{pixee_branch_name}' for SCM lookup[/dim]")
            scan_id, analysis_id = upload_to_pixee(
                output_filename,
                pixee_repository_id,
                pixee_api_key,
                pixee_branch_name,
                pixee_base_url,
                session,
                trigger_analysis,
                integration_id,
            )
            console.print(f"[green]✓[/green] Successfully uploaded to Pixee!")
            console.print(f"  Scan ID: {scan_id}")
            scan_url = f"{pixee_base_url}/scans/{scan_id}"
            console.print(f"  Scan URL: [link={scan_url}]{scan_url}[/link]")

            if analysis_id:
                analysis_url = f"{pixee_base_url}/analysis/{analysis_id}"
                console.print(f"  Analysis ID: {analysis_id}")
                console.print(f"  Analysis URL: [link={analysis_url}]{analysis_url}[/link]")
            elif trigger_analysis:
                console.print(f"[yellow]Note: Analysis was triggered but response did not include analysis ID[/yellow]")
            else:
                console.print(f"[dim]Note: Analysis not triggered. Use --trigger-analysis flag to automatically trigger analysis.[/dim]")

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
