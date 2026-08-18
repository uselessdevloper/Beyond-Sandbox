import os
import subprocess
import sys

def vulnerable_ping():
    # 1. Taint source from system arguments
    target = sys.argv[1] 
    os.system("ping -c 4 " + target) 

def vulnerable_subprocess(request):
    # 2. Taint source from a web request
    user_cmd = request.GET['cmd']
    subprocess.Popen(user_cmd, shell=True) 

def safe_ls():
    # 3. Trusted constant string (no taint) - Scanner should ignore this
    os.system("ls -la")