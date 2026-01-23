from pwn import p64, xor

cipher = p64(0x544a15120b72546e)
cipher += p64(0x5540501e0b055157)
cipher += p64(0x545d5c5c5154540b)
cipher += p64(0x691f5e0771171749)
key = b"XaDht-+1432=/as4?0129mklqt!@cnz^"

print(f"Flag: {xor(cipher, key).decode()}")
