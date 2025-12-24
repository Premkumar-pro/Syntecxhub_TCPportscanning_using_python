import socket
import threading
import base64

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad

SERVER_IP = "127.0.0.1"
PORT = 5555
PRE_SHARED_KEY = "SecureChatKey123"

def derive_key(password):
    return SHA256.new(password.encode()).digest()

KEY = derive_key(PRE_SHARED_KEY)

def encrypt_message(msg):
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(msg.encode(), AES.block_size)))

def decrypt_message(data):
    raw = base64.b64decode(data)
    cipher = AES.new(KEY, AES.MODE_CBC, raw[:16])
    return unpad(cipher.decrypt(raw[16:]), AES.block_size).decode()

def receive(client):
    while True:
        print("\n[Message]:", decrypt_message(client.recv(4096)))

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER_IP, PORT))
print("[+] Connected to server")

threading.Thread(target=receive, args=(client,), daemon=True).start()

while True:
    msg = input("You: ")
    client.send(encrypt_message(msg))