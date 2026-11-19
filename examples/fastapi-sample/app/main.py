import base64
import hashlib
import pickle
import sqlite3
import subprocess

import requests
import yaml
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

SECRET_KEY = "dev-secret-key-please-change"                      # hardcoded secret
DB_PASSWORD = "Pa55w0rd-prod-db"                                 # hardcoded password
GITHUB_TOKEN = "ghp_a8Kx2mQz7RvT4pLw9NcB3yHd6JfE1sUg5VoX"        # fake token (gitleaks/trivy)
AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOP234567"                       # fake key

app = FastAPI(title="vulnerable sample", debug=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
_db.executemany("INSERT INTO items(name) VALUES (?)", [("alpha",), ("beta",)])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/items/{item_id}")
def get_item(item_id: str):
    rows = _db.execute("SELECT id, name FROM items WHERE id = %s" % item_id).fetchall()   # SQL injection
    return {"items": rows}


@app.post("/run")
async def run(request: Request):
    cmd = (await request.body()).decode()
    return {"rc": subprocess.call(cmd, shell=True)}                                       # command injection


@app.post("/load")
async def load(request: Request):
    return {"obj": repr(pickle.loads(base64.b64decode(await request.body())))}            # unsafe deserialization


@app.post("/yaml")
async def parse_yaml(request: Request):
    return {"doc": yaml.load((await request.body()).decode())}                            # unsafe yaml.load


@app.get("/fetch")
def fetch(url: str):
    return {"len": len(requests.get(url, verify=False, timeout=5).text)}                  # SSRF, TLS verify off


@app.get("/file")
def read_file(name: str):
    with open("/app/data/" + name) as f:                                                  # path traversal
        return {"content": f.read()}


@app.get("/greet", response_class=HTMLResponse)
def greet(name: str = "world"):
    return f"<html><body><h1>Hello {name}</h1></body></html>"                              # reflected XSS


@app.get("/hash")
def md5(value: str):
    return {"md5": hashlib.md5(value.encode()).hexdigest()}                               # weak hash
