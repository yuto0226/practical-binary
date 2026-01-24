from pwn import p64, p32, xor

stack_data = p64(0x6223331533216010)
stack_data += p64(0x6675364134766545)
stack_data += p64(0x6570331064756717)
stack_data += p64(0x6671671162763518)

key = p32(0x00400620)

flag = xor(stack_data, key)

print(f"Flag: {flag.decode()}")