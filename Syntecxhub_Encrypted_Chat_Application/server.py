import socket
import threading
import logging
import base64

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad

HOST = "0.0.0.0"
PORT = 5555
PRE_SHARED_KEY = "SecureChatKey123"
LOG_FILE = "chat_logs.txt"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

clients = []

def derive_key(password):
    return SHA256.new(password.encode()).digest()

KEY = derive_key(PRE_SHARED_KEY)

def encrypt_message(msg):
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(msg.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted)

def decrypt_message(data):
    raw = base64.b64decode(data)
    iv = raw[:16]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(raw[16:]), AES.block_size).decode()

def broadcast(msg, sender):
    for c in clients:
        if c != sender:
            c.send(msg)

def handle_client(client, addr):
    print(f"[+] Connected {addr}")
    clients.append(client)

    while True:
        try:
            data = client.recv(4096)
            if not data:
                break
            message = decrypt_message(data)
            print(addr, ":", message)
            logging.info(f"{addr}: {message}")
            broadcast(data, client)
        except:
            break

    clients.remove(client)
    client.close()
    print(f"[-] Disconnected {addr}")

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print("[+] Server started")

    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

start_server()