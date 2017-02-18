#!/usr/bin/env python2

import json
import os
from hashlib import sha256

import psycopg2
from psycopg2 import Binary


def create_db(cfg):
    conn = psycopg2.connect(user="postgres")
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute("CREATE DATABASE mail_encrypter")
    cur.execute("CREATE USER mail_encrypter WITH PASSWORD %s", (cfg['db_pass'],))
    cur.execute("GRANT ALL PRIVILEGES ON DATABASE mail_encrypter TO mail_encrypter")
    cur.close()
    conn.close()

    conn = psycopg2.connect(host=cfg['db_host'], database="mail_encrypter",
                            user="mail_encrypter", password=cfg['db_pass'])
    cur = conn.cursor()
    create_keys_table = '''
            CREATE TABLE IF NOT EXISTS keys (
                id SERIAL PRIMARY KEY,
                pass_hash TEXT NOT NULL,
                public BYTEA,
                private BYTEA
            )
        '''
    create_users_table = '''
            CREATE TABLE IF NOT EXISTS emails (
                email TEXT PRIMARY KEY,
                key INTEGER REFERENCES keys(id)
            )
        '''
    cur.execute(create_keys_table)
    cur.execute(create_users_table)
    conn.commit()
    cur.close()
    conn.close()


def populate_db(cfg):
    conn = psycopg2.connect(host=cfg['db_host'], database="mail_encrypter",
                            user="mail_encrypter", password=cfg['db_pass'])
    c = conn.cursor()

    for i in range(100000):
        c.execute("INSERT INTO keys(pass_hash, public, private) VALUES (%s, %s, %s)",
                  (sha256(str(i+1)).hexdigest(), Binary(os.urandom(300)), Binary(os.urandom(1300))))
        c.execute("INSERT INTO emails(email, key) VALUES (%s, %s)", (str(i+1) + "@gmail.com", i+1,))

    conn.commit()
    c.close()
    conn.close()


if __name__ == '__main__':
    config = json.loads(open("config.json").read())
    try:
        create_db(config)
    except Exception as e:
        print e
    populate_db(config)
