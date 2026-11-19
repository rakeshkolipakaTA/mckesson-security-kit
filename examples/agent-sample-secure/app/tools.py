import os

from agentsec import safe_fetch, safe_path

DATA_DIR = os.environ.get("DATA_DIR", "/app/data")
ALLOWED_HOSTS = ["api.example.com"]
OUTBOX = []


def read_file(path):
    return open(safe_path(DATA_DIR, path)).read(2000)


def http_fetch(url):
    status, body = safe_fetch(url, allow_hosts=ALLOWED_HOSTS)
    return f"{status} {body[:500].decode(errors='replace')}"


def delete_records(table):
    return f"deleted rows from {table}"


def send_email(to, body):
    OUTBOX.append((to, body))
    return f"email sent to {to}"


IMPLS = {"read_file": read_file, "http_fetch": http_fetch, "delete_records": delete_records, "send_email": send_email}
