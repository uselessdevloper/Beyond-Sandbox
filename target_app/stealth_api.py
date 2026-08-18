import sqlite3
import os
import subprocess
import sys
from fastapi import FastAPI, Request

app = FastAPI()

# =====================================================================
# PART 1: THE VOLUME STRESS TEST
# Goal: Flood the engine with 10 blatant findings to test stability.
# The scanner MUST catch all of these without crashing.
# =====================================================================

@app.get("/stress")
def stress_test(request: Request):
    user_input = request.query_params.get("data")
    
    # 5 Blatant SQL Injections (Testing all string formatting types)
    sqlite3.execute(f"SELECT * FROM patients WHERE id = {user_input}")
    sqlite3.execute("INSERT INTO logs VALUES (" + user_input + ")")
    sqlite3.execute("UPDATE config SET val = '%s'" % user_input)
    sqlite3.execute("DELETE FROM sessions WHERE v = {}".format(user_input))
    sqlite3.execute(f"DROP TABLE {user_input}")
    
    # 5 Blatant Command Injections
    os.system(f"echo {user_input}")
    os.system("ping -c 4 " + user_input)
    subprocess.Popen(user_input, shell=True)
    subprocess.run(["sh", "-c", user_input])
    subprocess.call(f"cat {user_input}", shell=True)
    
    return {"status": "done"}


# =====================================================================
# PART 2: THE EVASION TEST (GHOST VULNERABILITIES)
# Goal: Defeat the SAST scanner using advanced Python execution tricks.
# The scanner will likely MISS all of these.
# =====================================================================

@app.get("/evade_regex")
def evade_regex(request: Request):
    """
    EVASION 1: Unmodeled String Transformations.
    The TaintEvaluator understands `+` and `f-strings`, but we haven't programmed 
    it to evaluate built-in methods like `.replace()` or `.join()` at runtime.
    Because this evaluates to `<CALL_replace>`, the SQL regex in the JSON config will fail to match it.
    """
    payload = request.query_params.get("id")
    obfuscated_sql = " S E L E C T * FROM users WHERE id = ".replace(" ", "")
    sqlite3.execute(obfuscated_sql + payload)


@app.get("/evade_sinks")
def evade_sinks(request: Request):
    """
    EVASION 2: Dynamic Dispatch.
    The engine looks for an ast.Call where the function name matches a known sink 
    (like "system" or "Popen"). Here, we hide the sink name by constructing it 
    dynamically as a string and invoking it via `getattr`.
    """
    cmd = request.query_params.get("cmd")
    
    # "sys" + "tem" = "system"
    hidden_sink_name = "sys" + "tem"
    
    # Grab the os.system function from the os module dynamically
    runner = getattr(os, hidden_sink_name)
    
    # Execute the payload
    runner(cmd)


class HealthBotCore:
    def __init__(self, untrusted_input):
        # Taint is stored in an object's state (attribute)
        self.diagnostic_query = untrusted_input
        
    def run_diagnostics(self):
        """
        EVASION 3: Object-Oriented State Isolation.
        Our Scope tracking handles local variables and simple reassignments beautifully.
        However, it does not trace data flow *across* class methods via `self`. 
        When the engine looks at `self.diagnostic_query` here, it appears as an untainted variable.
        """
        subprocess.Popen("diagnostic_script.sh " + self.diagnostic_query, shell=True)


@app.get("/evade_oop")
def evade_oop(request: Request):
    # Instantiate the class with the tainted web payload
    payload = request.query_params.get("q")
    bot = HealthBotCore(payload)
    
    # Execute the method. The SAST loses the taint trail here.
    bot.run_diagnostics()