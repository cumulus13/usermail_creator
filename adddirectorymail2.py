import paramiko
from configset import configset
from pathlib import Path
from pydebugger.debug import debug
# from paramiko import RSAKey

CONFIGFILE = str(Path(__file__).parent / 'addmailuser.ini')
CONFIG = configset(CONFIGFILE)

# Data login SSH
hostname = CONFIG.get_config('ssh', 'host')
port = int(CONFIG.get_config('ssh', 'port') or 22)
username = CONFIG.get_config('ssh', 'user') or 'root'
key_path = Path(CONFIG.get_config('ssh', 'key') or r'C:\Users\Admin\.ssh\id_rsa')
if not key_path.exists():
    print(f"Key not found: {key_path}")
    exit(1)

# Convert to string in Unix-like format
key_path = str(key_path).replace("\\", "/")

# Direktori yang akan dibuat
dir_path = CONFIG.get_config('vhost', 'dir') or '/var/mail/vhosts/licface.com'

# Membuat objek SSHClient
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# pkey = RSAKey.from_private_key_file(key_path)
try:
    # Koneksi ke server SSH menggunakan private key
    config = {
        'hostname': hostname,
        'port': port,
        'username': username,
        'key_filename': key_path,
        'look_for_keys': False,
        'allow_agent': False
    }
    debug(config = config, debug = 1)
    client.connect(**config)

    # Perintah untuk membuat direktori dan set owner
    command = f"mkdir -p {dir_path} && chown postfix:postdrop {dir_path}"

    stdin, stdout, stderr = client.exec_command(command)

    print("Output:")
    print(stdout.read().decode())

    error = stderr.read().decode()
    if error:
        print("Error:")
        print(error)

finally:
    client.close()
