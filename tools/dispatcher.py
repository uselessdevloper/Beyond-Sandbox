import json
import argparse
import os

def dispatch_findings(sast_file: str, web_out: str, local_out: str):
    if not os.path.exists(sast_file):
        print(f"Error: {sast_file} not found.")
        return

    with open(sast_file, 'r') as f:
        data = json.load(f)

    # Safely handle both {"issues": [...]} format and raw [...] format
    issues_list = data if isinstance(data, list) else data.get("issues", [])

    web_issues = []
    local_issues = []

    for issue in issues_list:
        # We check the rule ID (e.g., "SQLI_WEB_001" vs "CMD_LOCAL_001")
        # Safely grab the rule ID whether the SAST calls it 'rule_id', 'rule', or 'id'
        rule_id = issue.get("rule_id", issue.get("rule", issue.get("id", ""))).upper()

        if "WEB" in rule_id:
            web_issues.append(issue)
        elif "LOCAL" in rule_id:
            local_issues.append(issue)
        else:
            # Fallback: Untagged assumed web
            web_issues.append(issue)

    # Format the output to match the input structure
    if isinstance(data, list):
        web_data = web_issues
        local_data = local_issues
    else:
        web_data = {"version": data.get("version", "1.0"), "issues": web_issues}
        local_data = {"version": data.get("version", "1.0"), "issues": local_issues}

    # Write the Web Queue
    with open(web_out, 'w') as f:
        json.dump(web_data, f, indent=2)

    # Write the Local Queue
    with open(local_out, 'w') as f:
        json.dump(local_data, f, indent=2)

    print(f"Dispatch Complete!")
    print(f"  → Routed {len(web_issues)} findings to WEB queue ({web_out})")
    print(f"  → Routed {len(local_issues)} findings to LOCAL queue ({local_out})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAST Finding Dispatcher")
    parser.add_argument("--sast-json", required=True, help="Original SAST output JSON")
    parser.add_argument("--web-out", default="sast_web_queue.json", help="Output file for Fuzzer")
    parser.add_argument("--local-out", default="sast_local_queue.json", help="Output file for DAST")
    args = parser.parse_args()
    
    dispatch_findings(args.sast_json, args.web_out, args.local_out)