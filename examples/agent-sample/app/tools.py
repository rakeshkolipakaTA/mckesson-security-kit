import sqlite3
import ssl
import subprocess
import urllib.request

from .framework import tool

BASE = "/app/data/"
OUTBOX = []
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
_db.execute("INSERT INTO customers(name, email) VALUES ('Ada', 'ada@example.com')")


@tool
def read_file(path):
    with open(BASE + path) as f:                                   # path traversal: model/user controls `path`
        return f.read(2000)


@tool
def http_fetch(url):
    ctx = ssl._create_unverified_context()                         # TLS verification off
    return urllib.request.urlopen(url, context=ctx, timeout=5).read(2000).decode(errors="replace")   # SSRF: any URL


@tool
def python_exec(code):
    out = {}
    exec(code, {}, out)                                            # model-written code runs in the service process
    return str(out)[:500]


@tool
def sql_query(sql):
    return str(_db.execute(sql).fetchall())                        # model-written SQL runs verbatim


@tool
def delete_records(table):
    _db.execute("DELETE FROM " + table)                            # irreversible, no human approval
    return f"deleted all rows from {table}"


@tool
def send_email(to, body):
    OUTBOX.append((to, body))                                      # irreversible, no human approval, any recipient
    return f"email sent to {to}"


def shell(cmd):
    return subprocess.check_output(cmd, shell=True)                # unused helper left in the codebase
