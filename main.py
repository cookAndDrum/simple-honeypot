# logger
# ssh server
# emulated shell env
# multi threading
# deploy
#
# logging detail with ip geolocation
# rate limiting to prevent flooding
# alert for repeated attempt from same source
# basic command simulation
import paramiko
import datetime
import threading
import socket
import logging
from logging.handlers import RotatingFileHandler 


server_key = paramiko.RSAKey(filename='server.key')

def info_logger(name, log_file):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(log_file, maxBytes=2000, backupCount=5)
    handler.setFormatter(log_format)
    logger.addHandler(handler)
    return logger, handler


log_format = logging.Formatter("%(asctime)s %(message)s")

# for all caught logger
funnel_logger, funnel_handler = info_logger('funnel_logger', 'cmd_audits.log')
# for cred logger, IP, username, password, and maybe geolocation later
cred_logger, cred_handler = info_logger('cred_logger', 'cred_audits.log')


# paramiko uses ssh2
class SSHServer(paramiko.server.ServerInterface):
    def log_auth_attempt(self, username, pwd):
        print(f"Login attempt: {username} {pwd}")
        with open('login_attempt.txt', 'a') as file:
            file.write(
                f"{datetime.datetime.now()} - Login attempt: {username}:{pwd}")
        return paramiko.AUTH_FAILED


def handle_conn(client_socket, addr):
    # trasport class handle the ssh transport layer (protocol nego, enc, auth)
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(server_key)
    server = SSHServer()
    transport.start_server(server=server)
    channel = transport.accept(1)
    if channel is None:
        print("No channel")
        transport.close()


def start_server():
    port = 2222
    ip = '0.0.0.0'
    # https://realpython.com/python-sockets/#background
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    sock.listen(100)
    print(f"Honeypot is listening on port {port}...")

    while True:
        client, addr = sock.accept()
        print(f"Connection from: {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_conn, args=(client, addr)).start()


if __name__ == '__main__':
    start_server()
