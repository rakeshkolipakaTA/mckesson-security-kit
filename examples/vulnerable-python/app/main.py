import hashlib, pickle, subprocess, yaml, sqlite3

DB_PASSWORD = "SuperSecret123!"                      # B105 hardcoded password
GITHUB_TOKEN = "ghp_a8Kx2mQz7RvT4pLw9NcB3yHd6JfE1sUg5VoX"  # fake token for gitleaks

def run(cmd):
    return subprocess.call(cmd, shell=True)           # B602 shell=True

def load(blob):
    return pickle.loads(blob)                         # B301 unsafe deserialization

def parse(text):
    return yaml.load(text)                            # B506 unsafe yaml load

def digest(pw):
    return hashlib.md5(pw.encode()).hexdigest()       # B324 weak hash

def user(name):
    c = sqlite3.connect("x.db")
    return c.execute("SELECT * FROM u WHERE n='%s'" % name)  # B608 SQL injection
