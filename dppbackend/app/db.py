import pymysql
import pymysql.cursors
from flask import current_app


def get_connection():
    cfg = current_app.config
    return pymysql.connect(
        host     = cfg["DB_HOST"],
        port     = cfg["DB_PORT"],
        user     = cfg["DB_USER"],
        password = cfg["DB_PASSWORD"],
        database = cfg["DB_NAME"],
        charset  = "utf8mb4",
        cursorclass = pymysql.cursors.DictCursor,
        autocommit  = True,
    )


def fetch_one(sql, params=()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def fetch_all(sql, params=()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def execute(sql, params=()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.lastrowid
