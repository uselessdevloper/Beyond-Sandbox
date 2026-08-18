import sqlite3
from sqlite3 import execute as run_query
import sys
import os

def vulnerable_concat_test(request):
    # 1. Deep reassignment + String Concat + Taint Source
    a = request.GET['user']
    b = a
    c = b
    d = "SELECT * FROM users WHERE id = " + c 
    db.execute(d) # [FLAGGED] (Fixes recursion depth limit)

def safe_parameterized():
    # 2. Parameterized Query Extraction
    user_input = os.environ.get("USER")
    query = "SELECT * FROM items WHERE owner = ?"
    cursor.execute(query, (user_input,)) # [SAFE] (user_input is in arg 1, not arg 0)

def f_string_test(input_val):
    # 3. F-Strings and Kwargs
    sql_str = f"DELETE FROM data WHERE id = {input_val}"
    db.execute(sql=sql_str) # [FLAGGED] (Fixes arg extraction false negative)

def aliased_import_test():
    # 4. Aliased Imports & Alternate SQL Words
    val = input("Drop table name: ")
    cmd = "TRUNCATE TABLE %s" % val
    run_query(cmd) # [FLAGGED] (Fixes Import Alias + TRUNCATE detection)

def english_false_positive_test():
    # 5. English string false positive prevention
    message = "I want to SELECT the best update strategy for my delete operation."
    print(message)
    # Even if executed, it doesn't structurally start with a SQL verb, lowering confidence/ignoring
    cursor.execute(message) # [SAFE/IGNORED]

def safe_constant_test():
    # 6. Distinguishing Trusted Constants
    table_name = "products"
    query = f"SELECT * FROM {table_name}"
    db.execute(query) # [SAFE] (No untrusted taint in the evaluation tree)

def invalid_syntax_test():
    # 7. Robustness (No crash)
    # eval("this is invalid python code !@#)
    pass