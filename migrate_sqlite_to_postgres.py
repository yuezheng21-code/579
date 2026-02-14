#!/usr/bin/env python3
"""One-off SQLite -> PostgreSQL migration helper for Railway."""
import argparse
import os
import re
import sqlite3
from typing import List, Tuple

TYPE_MAP = {
    "INTEGER": "BIGINT",
    "REAL": "DOUBLE PRECISION",
    "TEXT": "TEXT",
    "BLOB": "BYTEA",
    "NUMERIC": "NUMERIC",
    "BOOLEAN": "BOOLEAN",
}


def map_sqlite_type(t: str) -> str:
    t = (t or "TEXT").upper()
    for k, v in TYPE_MAP.items():
        if k in t:
            return v
    return "TEXT"


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def fetch_tables(sconn: sqlite3.Connection) -> List[str]:
    rows = sconn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def build_create_table_sql(sconn: sqlite3.Connection, table: str, schema: str) -> str:
    cols = sconn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()
    pk_cols = [c[1] for c in cols if c[5] > 0]

    col_defs = []
    for _, name, ctype, notnull, dflt, _ in cols:
        col_sql = [quote_ident(name), map_sqlite_type(ctype)]
        if notnull:
            col_sql.append("NOT NULL")
        if dflt is not None:
            # Normalize SQLite datetime default syntax for Postgres
            d = str(dflt)
            if re.search(r"datetime\('now'\)", d, re.I):
                d = "CURRENT_TIMESTAMP"
            col_sql.append(f"DEFAULT {d}")
        col_defs.append(" ".join(col_sql))

    if pk_cols:
        pk_expr = ", ".join(quote_ident(c) for c in pk_cols)
        col_defs.append(f"PRIMARY KEY ({pk_expr})")

    table_ident = f'{quote_ident(schema)}.{quote_ident(table)}'
    return f"CREATE TABLE IF NOT EXISTS {table_ident} (\n  " + ",\n  ".join(col_defs) + "\n)"


def copy_table_data(sconn: sqlite3.Connection, pconn, table: str, schema: str, truncate: bool):
    from psycopg2 import sql
    from psycopg2.extras import execute_values
    cols = sconn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()
    col_names = [c[1] for c in cols]
    if not col_names:
        return 0

    table_ident = sql.Identifier(schema, table)
    col_idents = [sql.Identifier(c) for c in col_names]

    with pconn.cursor() as cur:
        if truncate:
            cur.execute(sql.SQL("TRUNCATE TABLE {} RESTART IDENTITY CASCADE").format(table_ident))

        rows = sconn.execute(f"SELECT * FROM {quote_ident(table)}").fetchall()
        if not rows:
            return 0

        insert_sql = sql.SQL("INSERT INTO {} ({}) VALUES %s").format(
            table_ident,
            sql.SQL(", ").join(col_idents),
        )
        execute_values(cur, insert_sql.as_string(pconn), [tuple(r) for r in rows], page_size=500)
        return len(rows)


def main():
    parser = argparse.ArgumentParser(description="Migrate SQLite DB to PostgreSQL")
    parser.add_argument("--sqlite-path", default=os.environ.get("SQLITE_PATH", "hr_system.db"))
    parser.add_argument("--postgres-url", default=os.environ.get("DATABASE_URL"), required=False)
    parser.add_argument("--schema", default="public")
    parser.add_argument("--truncate", action="store_true", help="truncate destination tables before import")
    args = parser.parse_args()

    if not args.postgres_url:
        raise SystemExit("Missing PostgreSQL URL. Provide --postgres-url or set DATABASE_URL.")

    import psycopg2
    from psycopg2 import sql

    sconn = sqlite3.connect(args.sqlite_path)
    sconn.row_factory = sqlite3.Row
    pconn = psycopg2.connect(args.postgres_url)
    pconn.autocommit = False

    try:
        tables = fetch_tables(sconn)
        print(f"Found {len(tables)} tables in SQLite.")

        with pconn.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(args.schema)))

        for t in tables:
            create_sql = build_create_table_sql(sconn, t, args.schema)
            with pconn.cursor() as cur:
                cur.execute(create_sql)

        total = 0
        for t in tables:
            n = copy_table_data(sconn, pconn, t, args.schema, args.truncate)
            total += n
            print(f"{t}: migrated {n} rows")

        pconn.commit()
        print(f"Done. Total rows migrated: {total}")
    except Exception:
        pconn.rollback()
        raise
    finally:
        sconn.close()
        pconn.close()


if __name__ == "__main__":
    main()
