import paramiko
from configset import configset
from pathlib import Path
from pydebugger.debug import debug


def add_folder(usermail):
    domain = ''
    if '@' in usermail:
        domain = usermail.split('@')[1]
        usermail = usermail.split('@')[0]
    
    
    CONFIGFILE = str(Path(__file__).parent / 'addmailuser.ini')
    CONFIG = configset(CONFIGFILE)

    # Data login SSH
    hostname = CONFIG.get_config('ssh', 'host')
    port = CONFIG.get_config('ssh', 'port') or 22
    username = CONFIG.get_config('ssh', 'user') or 'root'
    password = CONFIG.get_config('ssh', 'password') or 'root'

    # Direktori yang akan dibuat
    dir_path = CONFIG.get_config('vhost', 'dir') or '/var/mail/vhosts/{domain}'

    # Membuat objek SSHClient
    client = paramiko.SSHClient()

    # Menambahkan host ke known hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Koneksi ke server SSH
        client.connect(hostname, port=port, username=username, password=password)

        # Perintah untuk membuat direktori
        dest_path = str(Path(dir_path, usermail).as_posix())
        command = f"mkdir -p {dest_path} && chown postfix:postdrop {dest_path} && chmod -R 777 {dest_path}"
        debug(command = command)
        # command = 'df -h'

        # Menjalankan perintah
        stdin, stdout, stderr = client.exec_command(command)

        # Menampilkan output dari perintah
        print("Output:")
        print(stdout.read().decode())

        # Menampilkan error (jika ada)
        error = stderr.read().decode()
        if error:
            print("Error:")
            print(error)

    finally:
        # Menutup koneksi SSH
        client.close()

if __name__ == '__main__':
    import sys
    add_folder(sys.argv[1])