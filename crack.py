from pwn import *
from base64 import b64encode, b64decode

context.arch = 'amd64'
exe = './oracle'
io = process([exe])
leaked_blocks = b''
leaked_bytes = b''

def printBytes(bytes):
  print(" ".join('{:02x}'.format(x) for x in bytes))

def bruteForce(block, target, pad):
  offset = block*16
  for i in range(256):
    testByte = i.to_bytes(1, 'big')
    payload =  pad + testByte
    #print(payload)
    io.recvuntil(b'(b64): ')
    io.sendline(b64encode(payload))
    io.recvuntil(b'(b64): ')
    temp_ciphertext = b64decode(io.recvuntil(b'\n')[:-1])
    for j in range(offset, offset+16, 1):
      if temp_ciphertext[j] != target[j+offset]:
        break
      if j==offset+15:
        return testByte
  print("Error, no match with pad ", pad)

io.recvuntil(b'(b64): ')
ciphertext = b64decode(io.recvuntil(b'\n')[:-1])
print(len(ciphertext))
print("Ciphertext:")
print(ciphertext)
print("Ciphertext raw bytes:")
printBytes(ciphertext)
print("\nRunning...")

for block in range(len(ciphertext)//16):
  print("\nBlock ", block, "\n~~~~~~~~~~")
  for i in range(15, -1, -1):
    pad = b'A' * i
    pad += leaked_blocks
    #print("Pad: ", pad)
    io.recvuntil(b'(b64): ')
    io.sendline(b64encode(pad))
    io.recvuntil(b'(b64): ')
    target_ciphertext = b64decode(io.recvuntil(b'\n')[:-1])
    #print("Target ciphertext:")
    #printBytes(target_ciphertext)
    byte_match = bruteForce(block, target_ciphertext, pad + leaked_bytes)
    print("Byte ", i, " match: ", byte_match)
    if byte_match != None:
      leaked_bytes += byte_match

  leaked_blocks += leaked_bytes
  print("=============")
  print("Leaked block:")
  print(leaked_bytes)
  leaked_bytes = b''

print("\n\nEND")
print("**********\nLeaked:")
print(leaked_blocks)
print()
#io.interactive()
