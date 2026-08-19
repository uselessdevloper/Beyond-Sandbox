import argparse
import logging
import os
import subprocess
import sys

# Configure logging for the handler
logging.basicConfig(level=logging.INFO, format="[PIPELINE] %(asctime)s - %(levelname)s: %(message)s")

def run_command(step_name: str, cmd: list):
    """Executes a CLI command and halts the pipeline if it fails."""
    logging.info(f"--- Starting Step: {step_name} ---")
    logging.info(f"Command: {' '.join(cmd)}")
    
    try:
        # We use subprocess.run to execute the command exactly as if typed in the terminal
        result = subprocess.run(cmd, check=True, text=True)
        logging.info(f"--- Step Completed: {step_name} ---\n")
    except subprocess.CalledProcessError as e:
        logging.error(f"Pipeline failed at '{step_name}' (Exit Code: {e.returncode})")
        sys.exit(e.returncode)
    except FileNotFoundError:
        logging.error(f"Failed to find executable for '{step_name}'. Ensure files exist.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Master Pipeline Handler for SAST/DAST Automation")
    parser.add_argument("--src-dir", default="../target_app", help="Path to target source code")
    parser.add_argument("--sast-out", default="sast_web_queue.json", help="Expected SAST output file")
    parser.add_argument("--dast-out", default="report.json", help="Expected DAST final report file")
    args = parser.parse_args()

    # Ensure we run commands from the directory where this handler is located
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(tools_dir)

    logging.info("Initializing Automated Security Pipeline...")

    # =========================================================================
    # STEP 1: STATIC ANALYSIS (SAST)
    # =========================================================================
    # Assuming sast_scanner.py analyzes the source and generates sast_web_queue.json
    # Adjust the arguments below to match your sast_scanner.py requirements
    sast_cmd = [
        sys.executable, "sast_scanner.py",
        "--src-dir", args.src_dir,
        "--out", args.sast_out
    ]
    # Uncomment the line below to activate SAST in the pipeline once ready
    # run_command("SAST Code Scan", sast_cmd)


    # =========================================================================
    # STEP 2: DYNAMIC ORCHESTRATION & FUZZING (DAST)
    # =========================================================================
    # Runs the web orchestrator with the exact parameters we perfected
    dast_cmd = [
        sys.executable, "web_orchestor.py",
        "--sast-json", args.sast_out,
        "--src-dir", args.src_dir,
        "--max-apps", "3",
        "--out", args.dast_out
    ]
    
    # We check if the SAST JSON actually exists before trying to orchestrate it
    if not os.path.exists(args.sast_out):
        logging.warning(f"SAST queue '{args.sast_out}' not found. Did the scanner run?")
    else:
        run_command("DAST Web Orchestrator", dast_cmd)


    # =========================================================================
    # STEP 3: OUTPUT PARSING & PUBLISHING (PLACEHOLDER)
    # =========================================================================
    logging.info("--- Starting Step: Result Processing ---")
    
    if os.path.exists(args.dast_out):
        logging.info(f"Found DAST report: {args.dast_out}. Processing results...")
        
        # TODO: Add your logic here to ingest report.json
        # Examples:
        # - Convert JSON to an HTML dashboard
        # - Push results to a Slack webhook or Jira API
        # - Fail the CI/CD pipeline if vulnerabilities > 0
        
        pass 
    else:
        logging.error("DAST report was not generated. Skipping output processing.")

    logging.info("--- Pipeline Execution Finished Successfully ---")

if __name__ == "__main__":
    main()