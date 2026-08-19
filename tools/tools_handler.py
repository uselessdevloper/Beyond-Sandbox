import logging
import os
import subprocess
import sys
import time
# Configure logging for the handler
logging.basicConfig(level=logging.INFO, format="[PIPELINE] %(asctime)s - %(levelname)s: %(message)s")

def run_command(step_name: str, cmd: list, allowed_exit_codes=(0,)):
    """Executes a CLI command and halts the pipeline if it fails."""
    logging.info(f"--- Starting Step: {step_name} ---")
    logging.info(f"Command: {' '.join(cmd)}")
    
    try:
        # Run without check=True so we don't automatically crash on a 1
        result = subprocess.run(cmd, text=True)
        
        # Check if the tool exited with an expected code (e.g., 0 for clean, 1 for vulns found)
        if result.returncode not in allowed_exit_codes:
            logging.error(f"Pipeline failed at '{step_name}' (Exit Code: {result.returncode})")
            sys.exit(result.returncode)
            
        logging.info(f"--- Step Completed: {step_name} ---\n")
    except FileNotFoundError:
        logging.error(f"Failed to find executable for '{step_name}'. Ensure files exist.")
        sys.exit(1)

def main():
    # Ensure we run commands from the directory where this handler is located
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(tools_dir)

    logging.info("Initializing Automated Security Pipeline...")

    # =========================================================================
    # STEP 1: STATIC ANALYSIS (SAST)
    # =========================================================================
    sast_cmd = [
        sys.executable, "sast_scanner.py",
        "--aggressive",
        "--format", "json",
        "--output", "sast_results.json"
    ]
    run_command("SAST Code Scan", sast_cmd, allowed_exit_codes=(0, 1))

    time.sleep(2)

    # =========================================================================
    # STEP 2: DISPATCHER
    # =========================================================================
    dispatcher_cmd = [
        sys.executable, "dispatcher.py",
        "--sast-json", "sast_results.json"
    ]
    run_command("SAST Dispatcher", dispatcher_cmd, allowed_exit_codes=(0,))

    time.sleep(2)


    # =========================================================================
    # STEP 3: DYNAMIC ORCHESTRATION & FUZZING (DAST)
    # =========================================================================
    dast_cmd = [
        sys.executable, "web_orchestor.py",
        "--sast-json", "sast_web_queue.json",
        "--src-dir", "../target_app",
        "--max-apps", "3",
        "--out", "report.json"
    ]
    run_command("DAST Web Orchestrator", dast_cmd, allowed_exit_codes=(0, 1))

    time.sleep(2)

    # =========================================================================
    # STEP 3B: DYNAMIC ORCHESTRATION (LOCAL CLI)
    # =========================================================================
    
    # if os.path.exists("sast_local_queue.json"):
    #     local_dast_cmd = [
    #         sys.executable, "local_fuzzer.py",
    #         "--sast-json", "sast_local_queue.json",
    #         "--src-dir", "../target_app",
    #         "--out", "local_report.json"
    #     ]
    #     run_command("DAST Local Orchestrator", local_dast_cmd, allowed_exit_codes=(0, 1))


    # =========================================================================
    # STEP 4: OUTPUT PARSING & PUBLISHING (PLACEHOLDER)
    # =========================================================================
    logging.info("--- Starting Step: Result Processing ---")
    
    if os.path.exists("report.json"):
        logging.info("Found DAST report: report.json. Processing results...")
        
        # TODO: Add your logic here to ingest report.json
        # Examples:
        # - Convert JSON to an HTML dashboard
        # - Fail the CI/CD pipeline if vulnerabilities > 0
        
        pass 
    else:
        logging.error("DAST report was not generated. Skipping output processing.")

    logging.info("--- Pipeline Execution Finished Successfully ---")

if __name__ == "__main__":
    main()