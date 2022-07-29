from socket import socket, AF_INET, SOCK_DGRAM
opcode = 1   # RRQ
filename = b'dados2.txt\x00'
mode = b'octet\x00'
rrq = struct.pack('!H11s6s', opcode, filename, mode)
s = socket(AF_INET, SOCK_DGRAM)
s.sendto(rrq, server_addr)
dados = s.recvfrom(8192)
