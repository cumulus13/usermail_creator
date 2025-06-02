
# User Mail Creator

  

A Python script to add a user to the mail database (Postfix + Dovecot + MySQL). This script hashes the user's password using Dovecot's `SHA256-CRYPT` and inserts the user into the database.

  

## Features

  

- Hashes passwords securely using Dovecot's `SHA256-CRYPT`.

- Inserts user data into the `virtual_users` table in the MySQL database.

- Retrieves domain IDs from the `virtual_domains` table.

- Configurable database connection via `.ini` configuration file.

  

## Requirements

  

- Python 3.8 or higher

- MySQL database

- Dovecot installed (for `doveadm` command)

- Required Python packages:

-  `mysql-connector-python`

-  `rich`

-  `pydebugger`

  

## Usage

```bash

usage: addmailuser.py [-h] [-l] [email] [password]

  

Insert a user into the mail database (Postfix + Dovecot + MySQL).

  

positional arguments:

email Email address of the user

password Plaintext password of the user

  

options:

-h, --help show this help message and exit
-l, --list  List all users in the mail database

```

or just enter

  

## author

[Hadi Cahyadi](mailto:cumulus13@gmail.com)

  

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

  

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)

[Support me on Patreon](https://www.patreon.com/cumulus13)
