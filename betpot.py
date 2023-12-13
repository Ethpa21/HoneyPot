import paramiko
import socket
import threading
import logging

from paramiko.pkey import PKey

class HoneypotSSHServer(paramiko.ServerInterface):

    def __init__(self):
        self.log = logging.getLogger('honeypot')
        super().__init__()

    def check_auth_password(self, username: str, password: str) -> int:
        
        self.log.info(f"Password Auth Attempt - {username}:{password}")
        print(f"{username}:{password}") 
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: PKey) -> int:
        
        self.log.info(f"Public Key Auth Attempt - {username}:{key}") 
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        
        return 'password,publickey'


def handle_connection(client_sock):
    transport = paramiko.Transport(client_sock)
    server_key = paramiko.RSAKey.from_private_key_file('key')
    transport.add_server_key(server_key)

    
    ssh = HoneypotSSHServer()
    transport.start_server(server=ssh)

    
    client_ip, client_port = client_sock.getpeername()
    logging.info(f"Connection from {client_ip}:{client_port}")

    try:
        
        channel = transport.accept(20)
        if channel is not None:
            channel.send("Welcome to the honeypot!\r\n")
            channel.close()

    except Exception as e:
        logging.error(f"Error handling connection: {e}")

    finally:
        transport.close()


def main():
    
    logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', 2222))  
    server_sock.listen(5)

    logging.info("Honeypot SSH Server started on port 2222...")

    while True:
        
        client_sock, _ = server_sock.accept()

        
        t = threading.Thread(target=handle_connection, args=(client_sock,))
        t.start()

if __name__ == "__main__":
    main()
