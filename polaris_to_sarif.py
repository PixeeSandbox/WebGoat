#!/usr/bin/env python3
"""
Generate SARIF output from Polaris findings API

Usage:
    python3 polaris_to_sarif.py --project-id <project_id> --api-token <token> [--output sarif.json] [--test-id latest]
"""

import argparse
import json
import sys
import urllib.request
import urllib.parse
import hashlib
import uuid
from typing import Dict, List, Any, Optional


def get_polaris_issues(project_id: str, api_token: str, test_id: str = "latest", base_url: str = "https://polaris.blackduck.com") -> List[Dict]:
    """Fetch issues from Polaris findings API"""
    # Build URL manually to match working curl command format
    full_url = f"{base_url}/api/findings/issues?testId={test_id}&_first=100&_includeType=true&_includeOccurrenceProperties=true&_includeFirstDetectedOn=true&projectId={project_id}"

    req = urllib.request.Request(full_url)
    req.add_header("accept", "application/vnd.polaris.findings.issues-1+json")
    req.add_header("Api-token", api_token)

    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        return data.get("_items", [])


def get_occurrence_details(occurrence_url: str, api_token: str) -> Dict:
    """Fetch occurrence details including file paths"""
    req = urllib.request.Request(occurrence_url)
    req.add_header("accept", "application/vnd.polaris.findings.occurrences-1+json")
    req.add_header("Api-token", api_token)

    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode())


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

    # Build rule ID based on issue type
    # For SAST: checker:kind|language (e.g., "hardcoded_credentials:password|java")
    # For SCA: vulnerability-id (e.g., "CVE-2025-11226")
    if "checker" in props:
        # SAST issue - build from checker, kind, and language
        checker = props.get("checker", "").lower()
        kind = props.get("kind", "").lower()
        language = props.get("language", "").lower().replace(" ", "_")

        if kind:
            rule_id = f"{checker}:{kind}|{language}"
        else:
            rule_id = f"{checker}|{language}"
    else:
        # SCA issue - use vulnerability ID
        rule_id = props.get("vulnerability-id", issue.get("weaknessId", issue["id"]))

    # Get severity
    severity = props.get("severity", "medium")

    # Build help text
    help_text = description_detail or props.get("description", issue_name)
    help_markdown = f"## Description\n{help_text}\n\n"

    if remediation:
        help_markdown += f"## Remediation\n{remediation}\n\n"

    # Add CVE/vulnerability info
    if "vulnerability-id" in props:
        help_markdown += f"## Vulnerability\n{props['vulnerability-id']}\n\n"
        if "overall-score" in props:
            help_markdown += f"**CVSS Score:** {props['overall-score']}\n\n"

    # Extract CWE tags
    tags = ["security"]
    cwes = extract_cwe_from_properties(props)
    tags.extend(cwes)

    # Determine if it's SCA or SAST
    if issue_type.get("altName") == "Component vulnerability":
        tags.append("sca")
    else:
        tags.append("static_analysis")

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
    """Create a SARIF result from a Polaris issue"""
    # Build rule ID same as in create_sarif_rule
    if "checker" in props:
        checker = props.get("checker", "").lower()
        kind = props.get("kind", "").lower()
        language = props.get("language", "").lower().replace(" ", "_")
        if kind:
            rule_id = f"{checker}:{kind}|{language}"
        else:
            rule_id = f"{checker}|{language}"
    else:
        rule_id = props.get("vulnerability-id", issue.get("weaknessId", issue["id"]))

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
        # Simplified link format - actual format may need portfolio/app IDs
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

    # Build location
    locations = []

    # For SCA issues, use logical location instead of physical location
    # This avoids the analysis service trying to read non-existent dependency files
    if "component-name" in props and "component-version-name" in props:
        component_location = props.get("location", f"{props['component-name']} {props['component-version-name']}")

        # Create a logical location for the component (not a file path)
        # According to SARIF spec, logicalLocations is an array within the location object
        locations.append({
            "logicalLocations": [
                {
                    "name": props.get('component-name', 'unknown'),
                    "fullyQualifiedName": component_location,
                    "kind": "package"
                }
            ],
            "message": {
                "text": component_location
            }
        })

    # For SAST issues, get file path from occurrence
    if occurrence and "path" in occurrence:
        file_path = occurrence.get("path", "unknown")
        line_number = occurrence.get("line", 1)

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

    # Add additional properties
    if "overall-score" in props:
        result["properties"] = {
            "cvss_score": props["overall-score"]
        }

    return result


def convert_to_sarif(issues: List[Dict], api_token: str, project_id: str) -> Dict:
    """Convert Polaris issues to SARIF format"""
    rules = {}
    results = []

    for issue in issues:
        # Extract properties
        props = {p["key"]: p["value"] for p in issue.get("occurrenceProperties", [])}

        # Create rule (unique by rule ID)
        # Build rule ID same as in create_sarif_rule
        if "checker" in props:
            checker = props.get("checker", "").lower()
            kind = props.get("kind", "").lower()
            language = props.get("language", "").lower().replace(" ", "_")
            if kind:
                rule_id = f"{checker}:{kind}|{language}"
            else:
                rule_id = f"{checker}|{language}"
        else:
            rule_id = props.get("vulnerability-id", issue.get("weaknessId", issue["id"]))

        if rule_id not in rules:
            rules[rule_id] = create_sarif_rule(issue, props)

        # Get occurrence details if available
        occurrence = None
        for link in issue.get("_links", []):
            if link.get("rel") == "occurrence":
                try:
                    occurrence = get_occurrence_details(link["href"], api_token)
                except Exception as e:
                    print(f"Warning: Could not fetch occurrence details: {e}", file=sys.stderr)

        # Create result
        result = create_sarif_result(issue, props, occurrence, project_id=project_id)
        results.append(result)

    # Build SARIF document
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Polaris",
                        "informationUri": "https://polaris.blackduck.com",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }

    return sarif


def main():
    parser = argparse.ArgumentParser(description="Convert Polaris findings to SARIF format")
    parser.add_argument("--project-id", required=True, help="Polaris project ID")
    parser.add_argument("--api-token", required=True, help="Polaris API token")
    parser.add_argument("--test-id", default="latest", help="Test ID to query (default: latest)")
    parser.add_argument("--output", default="polaris-results.sarif.json", help="Output SARIF file")
    parser.add_argument("--base-url", default="https://polaris.blackduck.com", help="Polaris base URL")

    args = parser.parse_args()

    print(f"Fetching issues from Polaris for project {args.project_id}...", file=sys.stderr)
    issues = get_polaris_issues(args.project_id, args.api_token, args.test_id, args.base_url)
    print(f"Found {len(issues)} issues", file=sys.stderr)

    print("Converting to SARIF format...", file=sys.stderr)
    sarif = convert_to_sarif(issues, args.api_token, args.project_id)

    print(f"Writing SARIF output to {args.output}...", file=sys.stderr)
    with open(args.output, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"Successfully generated SARIF file: {args.output}", file=sys.stderr)
    print(f"Total rules: {len(sarif['runs'][0]['tool']['driver']['rules'])}", file=sys.stderr)
    print(f"Total results: {len(sarif['runs'][0]['results'])}", file=sys.stderr)


if __name__ == "__main__":
    main()
