import sys
import os

                             
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.orchestrator import run

if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
