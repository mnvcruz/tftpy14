"""
This module handles all TFTP related data structures and 
methods.

(C) João Galamba, 2022
"""
# pylint: disable=redefined-outer-name
# pylint: disable=no-name-in-module

import re
import struct 
import string
import ipaddress
from socket import (
    socket,
    herror,
    gaierror,
    gethostbyaddr,
    gethostbyname_ex,
    AF_INET, SOCK_DGRAM,
)
from typing import Tuple

################################################################################
##
##      PROTOCOL CONSTANTS AND TYPES
##
################################################################################

MAX_DATA_LEN = 512            # bytes (data field of a DAT packet)
INACTIVITY_TIMEOUT = 30       # segs
MAX_BLOCK_NUMBER = 2**16 - 1
DEFAULT_MODE = 'octet'
SOCKET_BUFFER_SIZE = 8192     # bytes

# TFTP message opcodes
RRQ = 1   # Read Request
WRQ = 2   # Write Request
DAT = 3   # Data transfer
ACK = 4   # Acknowledge DAT
ERR = 5   # Error packet; what the server responds if a read/write 
          # can't be processed, read and write errors during file 
          # transmission also cause this message to be sent, and 
          # transmission is then terminated. The error number gives a 
          # numeric error code, followed by an ASCII error message that
          # might contain additional, operating system specific 
          # information.

# TFTP standard error codes and messages
UNDEF_ERROR              = 0
FILE_NOT_FOUND           = 1
ACCESS_VIOLATION         = 2
DISK_FULL_ALLOC_EXCEEDED = 3
ILLEGAL_OPERATION        = 4
UNKNOWN_TRANSFER_ID      = 5
FILE_EXISTS              = 6
NO_SUCH_USER             = 7

ERROR_MSGS = {
    UNDEF_ERROR        : 'Undefined error.',
    FILE_NOT_FOUND     : 'File not found.',
    ACCESS_VIOLATION   : 'Access violation.',
    DISK_FULL_ALLOC_EXCEEDED : 'Disk full or allocation exceeded.',
    ILLEGAL_OPERATION   : 'Illegal TFTP operation.',
    UNKNOWN_TRANSFER_ID : 'Unknown transfer ID.',
    FILE_EXISTS         : 'File already exists.',
    NO_SUCH_USER        : 'No such user.'
}

INET4Address = Tuple[str, int]        # TCP/UDP address => IPv4 and port
# FileReference = Union[str, BinaryIO]  # A path or a file object

###############################################################
##
##      SEND AND RECEIVE MESSAGES
##
###############################################################

def get_file(serv_addr: INET4Address, file_name: str):
    """
    RRQ a file given by filename from a remote TFTP server given
    by serv_addr.
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        with open(file_name, 'wb') as file:
            sock.settimeout(INACTIVITY_TIMEOUT)
            rrq = pack_rrq(file_name)
            sock.sendto(rrq, serv_addr)
            next_block_num = 1

            while True:
                packet, new_serv_addr = sock.recvfrom(SOCKET_BUFFER_SIZE)
                opcode = unpack_opcode(packet)

                if opcode == DAT:
                    block_num, data = unpack_dat(packet)
                    if block_num != next_block_num:
                        raise ProtocolError(f'Invalid block number {block_num}')

                    file.write(data)

                    ack = pack_ack(next_block_num)
                    sock.sendto(ack, new_serv_addr)

                    if len(data) < MAX_DATA_LEN:
                        break

                elif opcode == ERR:
                    raise Err(*unpack_err(packet))

                else: # opcode not in (DAT, ERR):
                    raise ProtocolError(f'Invalid opcode {opcode}')

                next_block_num += 1
            #:
        #:
    #:
#:

# def get_file(server_add: INET4Address, file_name: str):
#     """
#     RRQ a file given by filename from a remote TFTP server given
#     by serv_addr.
#     """
# 1. Abrir ficheiro "file_name" para escrita
#
# 2. Criar socket DGRAM
#
# 3. Criar e enviar pacote RRQ através do socket
#
# 4. Ler/Esperar pelo próximo pacote: (é suposto ser um DAT)
#    .1 Obtivemos pacote => extrair o opcode 
#
#    .2 Que pacote recebemos?
#
#       Pacote DAT:
#           .1 Extrair block_number e dados do DAT
#
#           .2 SE for um block_number "esperado": 
#                   a) então guardamos os dados no ficheiro
#                   b) Construimos e enviamos ACK correspondente
#                   c) Se dimensão dos dados for inferior MAX_DATA_LEN (512B)
#                      terminar o RRQ (transferência chegou ao fim)
#              SENÃO se block_number "inválido": assinalar erro de protocolo e terminar RRQ
#
#       Pacote ERR: Assinalar o erro e terminamos RRQ
#
#       Outro pacote qq: Assinalar erro de protocolo
#
# 5. Voltar a 4
#:

def put_file(serv_addr: INET4Address, file_name: str):
    """
    WRQ a file given by filename to a remote TFTP server given
    by serv_addr.
    """
#:

################################################################################
##
##      PACKET PACKING AND UNPACKING
##
################################################################################

def pack_rrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rq(RRQ, filename, mode)
#:

def unpack_rrq(packet: bytes) -> Tuple[str, str]:
    return _unpack_rq(packet)
#:

def pack_wrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return _pack_rq(WRQ, filename, mode)
#:

def unpack_wrq(packet: bytes) -> Tuple[str, str]:
    return _unpack_rq(packet)
#:

def _pack_rq(opcode: int, filename: str, mode: str = DEFAULT_MODE) -> bytes:
    if not is_ascii_printable(filename):
        raise ValueError(f'Invalid filename {filename} (not ascii printable)')
    if mode != 'octet':
        raise ValueError(f'Invalid mode {mode}. Supported modes: octet.')

    pack_filename = filename.encode() + b'\x00'
    pack_mode = mode.encode() + b'\x00'
    pack_format = f'!H{len(pack_filename)}s{len(pack_mode)}s'
    return struct.pack(pack_format, opcode, pack_filename, pack_mode)
#:

def _unpack_rq(packet: bytes) -> Tuple[str, str]:
    filename_delim = packet.index(b'\x00', 2)
    filename = packet[2:filename_delim].decode()
    if not is_ascii_printable(filename):
        raise ValueError(f'Invalid filename {filename} (not ascii printable).')

    mode_delim = len(packet) - 1
    mode = packet[filename_delim + 1:mode_delim].decode()

    return (filename, mode)
#:

def pack_dat(block_number: int, data: bytes) -> bytes:
    if not 0 <= block_number <= MAX_BLOCK_NUMBER:
        ValueError(f'Invalid block number {block_number}')
    if len(data) > MAX_DATA_LEN:
        ValueError(f'Invalid data length {len(data)} ')
    fmt = f'!HH{len(data)}s'
    return struct.pack(fmt, DAT, block_number, data)
#:

def unpack_dat(packet: bytes) -> Tuple[int, bytes]:
    _, block_number = struct.unpack('!HH', packet[:4])
    return block_number, packet[4:]
#:

def pack_ack(block_number: int) -> bytes:
    if not 0 <= block_number <= MAX_BLOCK_NUMBER:
        ValueError(f'Invalid block number {block_number}')
    return struct.pack('!HH', ACK, block_number)
#:

def unpack_ack(packet: bytes) -> int:
    if len(packet) > 4:
        raise ValueError(f'Invalid packet length: {len(packet)}')
    return struct.unpack('!H', packet[2:4])[0]
#:

def unpack_opcode(packet: bytes) -> int:
    opcode, *_ = struct.unpack("!H", packet[:2])
    if opcode not in (RRQ, WRQ, DAT, ACK, ERR):
        raise ValueError(f'Unrecognized opcode {opcode}.')
    return opcode
#:

def unpack_err(packet: bytes) -> Tuple[int, str]:
    _, error_num, error_msg = struct.unpack(f'!HH{len(packet)-4}s', packet)
    return error_num, error_msg[:-1]
#:

################################################################################
##
##      ERRORS AND EXCEPTIONS
##
################################################################################

class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """
#:

class ProtocolError(NetworkError):
    """
    A protocol error like unexpected or invalid opcode, wrong block 
    number, or any other invalid protocol parameter.
    """
#:

class Err(Exception):
    """
    An error sent by the server. It may be caused because a read/write 
    can't be processed. Read and write errors during file transmission 
    also cause this message to be sent, and transmission is then 
    terminated. The error number gives a numeric error code, followed 
    by an ASCII error message that might contain additional, operating 
    system specific information.
    """
    def __init__(self, error_code: int, error_msg: bytes):
        super().__init__(f'TFTP Error {error_code}')
        self.error_code = error_code
        self.error_msg = error_msg.decode()
    #:
#:

################################################################################
##
##      COMMON UTILITIES
##      Mostly related to network tasks
##
################################################################################

def _make_is_valid_hostname():
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname):
        """
        From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        See also: https://en.wikipedia.org/wiki/Hostname (and the RFC 
        referenced there)
        """
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname
#:
is_valid_hostname = _make_is_valid_hostname()


def get_host_info(server_addr: str) -> Tuple[str, str]:
    """
    Returns the server ip and hostname for server_addr. This param may
    either be an IP address, in which case this function tries to query
    its hostname, or vice-versa.
    This functions raises a ValueError exception if the host name in
    server_addr is ill-formed, and raises NetworkError if we can't get
    an IP address for that host name.
    TODO: refactor code...
    """
    try:
        ipaddress.ip_address(server_addr)
    except ValueError:
        # server_addr not a valid ip address, then it might be a 
        # valid hostname
        # pylint: disable=raise-missing-from
        if not is_valid_hostname(server_addr):
            raise ValueError(f"Invalid hostname: {server_addr}.")
        server_name = server_addr
        try:
            # gethostbyname_ex returns the following tuple: 
            # (hostname, aliaslist, ipaddrlist)
            server_ip = gethostbyname_ex(server_name)[2][0]
        except gaierror:
            raise NetworkError(f"Unknown server: {server_name}.")
    else:  
        # server_addr is a valid ip address, get the hostname
        # if possible
        server_ip = server_addr
        try:
            # returns a tuple like gethostbyname_ex
            server_name = gethostbyaddr(server_ip)[0]
        except herror:
            server_name = ''
    return server_ip, server_name
#:

def is_ascii_printable(txt: str) -> bool:
    return not set(txt) - set(string.printable)
    # ALTERNATIVA: return set(txt).issubset(string.printable)
#:

if __name__ == '__main__':
    print()
    print("____ RRQ ____")
    rrq = pack_rrq('relatorio.pdf')
    print(rrq)
    filename, mode = unpack_rrq(rrq)
    print(f"Filename: {filename} Mode: {mode}")

    print()
    print("____ WRQ ____")
    wrq = pack_wrq('relatorio.pdf')
    print(wrq)
    filename, mode = unpack_wrq(wrq)
    print(f"Filename: {filename} Mode: {mode}")

#:
