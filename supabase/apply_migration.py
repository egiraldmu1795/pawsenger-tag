"""Apply migration.sql to Supabase Postgres directly (no CLI needed).
Reads the connection string from env SUPABASE_DB_URL or ~/.eab/supabase_db_url
(format: postgresql://postgres:REALPASSWORD@db.<ref>.supabase.co:5432/postgres).
Splits SQL dollar-quote-aware so $$ function bodies aren't broken on ';'."""
import os, sys, ssl
from pathlib import Path
from urllib.parse import urlparse, unquote
import pg8000.dbapi

HERE = Path(__file__).resolve().parent
SQL = (HERE / "migration.sql").read_text(encoding="utf-8")

db_url = os.environ.get("SUPABASE_DB_URL")
if not db_url:
    f = Path.home() / ".eab" / "supabase_db_url"
    db_url = f.read_text(encoding="utf-8").strip() if f.exists() else ""
if not db_url or "[YOUR-PASSWORD]" in db_url or "PASSWORD" in db_url.split("@")[0].split(":")[-1].upper():
    sys.exit("No real DB password. Set ~/.eab/supabase_db_url with the actual password (not the [YOUR-PASSWORD] placeholder).")


def split_sql(sql: str):
    stmts, buf, i, n, in_dollar = [], [], 0, len(sql), False
    while i < n:
        if sql[i:i+2] == "$$":
            in_dollar = not in_dollar; buf.append("$$"); i += 2; continue
        if not in_dollar:
            if sql[i:i+2] == "--":                      # line comment
                j = sql.find("\n", i); j = n if j == -1 else j
                buf.append(sql[i:j]); i = j; continue
            if sql[i] == ";":
                s = "".join(buf).strip()
                if s: stmts.append(s)
                buf = []; i += 1; continue
        buf.append(sql[i]); i += 1
    tail = "".join(buf).strip()
    if tail: stmts.append(tail)
    return stmts


u = urlparse(db_url)
host, port = u.hostname, (u.port or 5432)
user, pwd = u.username, unquote(u.password or "")
database = (u.path or "/postgres").lstrip("/") or "postgres"

# Verified TLS only — Supabase presents a publicly-trusted cert. Never disable verification
# on an internet DB connection (it would expose the password to MITM). If verify ever fails,
# diagnose it (CA bundle / pooler host), don't bypass.
ctx = ssl.create_default_context()
conn = pg8000.dbapi.connect(user=user, host=host, port=port, database=database, password=pwd, ssl_context=ctx)

cur = conn.cursor()
stmts = split_sql(SQL)
print(f"connected to {host} as {user}; applying {len(stmts)} statements...")
for k, s in enumerate(stmts, 1):
    head = " ".join(s.split())[:70]
    try:
        cur.execute(s)
        print(f"  [{k:>2}/{len(stmts)}] OK  {head}")
    except Exception as e:
        print(f"  [{k:>2}/{len(stmts)}] ERR {head}\n        -> {type(e).__name__}: {str(e)[:160]}")
conn.commit()

# verify
cur.execute("select count(*) from public.tags")
print("tags rows:", cur.fetchone()[0])
cur.execute("select count(*) from public.pet_profiles")
print("pet_profiles rows:", cur.fetchone()[0])
conn.close()
print("DONE")
