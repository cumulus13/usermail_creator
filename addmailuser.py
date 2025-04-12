#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Add a user to the mail database / Insert a user into the mail database (Postfix + Dovecot + MySQL)
# Usage: python addmailuser.py email password
# Author: cumulus13
# License: MIT
# Email: cumulus13 [at] gmail [dot] com
# created: 2025-03-21
# created in: 10 minutes

import sys
from ctraceback import CTraceback
sys.exc_info = CTraceback()
import subprocess
import mysql.connector
import MySQLdb  # Import MySQLdb from mysqlclient
import argparse
from configset import configset
from pathlib import Path
from getpass import getpass
from rich.console import Console  # Import Console from rich
from pydebugger.debug import debug  # Import the debug function
from passlib.hash import sha256_crypt  # Import sha256_crypt for password hashing

console = Console()  # Initialize the Console

class User:
    configname = str(Path(__file__).parent / Path(__file__).stem) + ".ini"
    debug(configname = configname)
    CONFIG = configset(configname)

    def __init__(self, email, password):
        self.email = email
        self.password = password

    def __str__(self):
        return f"User: {self.email}"

    def __repr__(self):
        return f"User({self.email})"
    
    @classmethod    
    def generate_sha256_crypt_password(cls, password: str) -> str:
        return sha256_crypt.hash(password)

    @classmethod    
    def hash_password(cls, password):
        """Hashes the password using Dovecot's SHA256-CRYPT."""
        result = subprocess.run(
            ["doveadm", "pw", "-s", "SHA256-CRYPT"],
            input=password,  # Pass the password as a string
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else None

    @classmethod
    def config(cls, email = None, password = None):
        """Configures the database connection."""
        domain_id = None
        debug(configname = cls.CONFIG.configname)
        debug(filename = cls.CONFIG.filename())
        debug(get_configfile = cls.CONFIG.get_configfile())
        debug(host = cls.CONFIG.get_config("db", "host"))
        
        host = cls.CONFIG.get_config("db", "host") or 'localhost'
        user = cls.CONFIG.get_config("db", "user") or 'mail_admin'
        password = cls.CONFIG.get_config("db", "password") or getpass("Enter DB password: ") or 'Xxxnuxer13'
        database = cls.CONFIG.get_config("db", "database") or 'mailserver'
        if password: cls.CONFIG.write_config("db", "password", password)
        if host: cls.CONFIG.write_config("db", "host", host)
        if user: cls.CONFIG.write_config("db", "user", user)
        if database: cls.CONFIG.write_config("db", "database", database)
        
        debug(email = email, password = password)     
        if email:
            if not '@' in email:
                console.print("Invalid email address.", style="white on black")  # Error message
                exit
        
            email = email.lower()
            debug(email = email)
            domain_id = email.split('@')[1]
            debug(domain_id = domain_id)
        
        db_config = {
            "host": host,
            "user": user,
            "password": password,
            "database": database,
        }
        
        debug(db_config = db_config, domain_id = domain_id)
        
        return db_config, domain_id
    
    @classmethod    
    def get_domain_id(cls, domain):
        """Gets the domain ID from the mail.virtual_domains table."""
        db_config, _ = cls.config()
        database = db_config["database"]
        
        conn = MySQLdb.connect(
            host=db_config["host"],
            user=db_config["user"],
            passwd=db_config["password"],
            db=database
        )
        query = f"""SELECT id FROM {database}.virtual_domains WHERE name = %s"""
        cursor = conn.cursor()
        cursor.execute(query, (domain,))
        result = cursor.fetchone()
        debug(result = result)
        cursor.close()
        conn.close()
        
        return result[0] if result else None

    @classmethod
    def check_domain(cls, email, database = None):
        """Checks if the domain ID exists in the mail.virtual_domains table. If not exists then insert."""
        db_config, domain_id = cls.config(email)
        debug(db_config = db_config)
        debug(domain_id = domain_id)
        database = database or db_config.get("database")
        debug(database = database)
        
        try:
            conn = MySQLdb.connect(
                host=db_config["host"],
                user=db_config["user"],
                passwd=db_config["password"],
                db=database
            )
            debug(conn = conn)
            cursor = conn.cursor()
            debug(cursor = cursor)
        except MySQLdb.Error as err:
            console.print(f"Database connection error: {err}", style="red")
            return None
        
        # Check if domain exists
        query = f"""SELECT name FROM {database}.virtual_domains WHERE name = %s"""
        debug(query = query)
        cursor.execute(query, (domain_id,))
        result = cursor.fetchone()
        debug(result = result)
        
        # If domain doesn't exist, insert it
        if not result:
            insert_query = f"""INSERT INTO {database}.virtual_domains (name) VALUES (%s)"""
            debug(insert_query = insert_query)
            cursor.execute(insert_query, (domain_id,))
            conn.commit()
            
            # Get the newly inserted domain id
            cursor.execute(query, (domain_id,))
            result = cursor.fetchone()
            debug(result = result)
            
        debug(result = result)
        cursor.close()
        conn.close()
        
        return result[0] if result else None
    
    @classmethod
    def insert_user(cls, email = None, hashed_password = None):
        """Inserts the user into the mail.virtual_users table."""
        if not email or not hashed_password:
            console.print("Email and password are required.", style="white on black")
            exit
            
        db_config, domain_id = User.config(email, hashed_password)
        debug(db_config = db_config)
        debug(domain_id = domain_id)
        database = db_config["database"]
        result_check_domain = cls.check_domain(email, database)
        debug(result_check_domain = result_check_domain)
        print("continue ................")
        conn = MySQLdb.connect(
            host=db_config["host"],
            user=db_config["user"],
            passwd=db_config["password"],
            db=database
        )
        cursor = conn.cursor()
        
        # Check if user exists
        check_query = f"""SELECT email FROM {database}.virtual_users WHERE email = %s"""
        debug(check_query = check_query)
        cursor.execute(check_query, (email,))
        if cursor.fetchone():
            console.print(f"User {email} already exists!", style="yellow")
            cursor.close()
            conn.close()
            return False
        
        # Insert new user
        query = f"""INSERT INTO {database}.virtual_users (domain_id, email, password) VALUES (%s, %s, %s)"""
        debug(query = query)
        cursor.execute(query, (cls.get_domain_id(domain_id), email, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Insert a user into the mail database (Postfix + Dovecot + MySQL).")
    parser.add_argument("email", help="Email address of the user", nargs='?')
    parser.add_argument("password", help="Plaintext password of the user", nargs='?')
    
    args = parser.parse_args()
    if not args.email: args.email = console.input("[bold #FF00FF]Enter email    : [/]")
    if not args.password: args.password = getpass("Enter password : ")
    
    if not args.email or not args.password:
        console.print("Email and password are required.", style="white on red")  # Error message
        exit
        
    # hashed_pw = User.hash_password(args.password)
    hashed_pw = User.generate_sha256_crypt_password(args.password)
    
    if hashed_pw:
        User.insert_user(args.email, hashed_pw)
        console.print(f"User {args.email} added successfully.", style="bold #0000FF")  # Success message
    else:
        console.print("Error hashing password.", style="white on black")  # Error message
