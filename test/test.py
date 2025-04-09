from Crypto.Cipher import AES
from Crypto.Util import Counter

data = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

# Create the counter object with a 128-bit block size (16 bytes)
counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))

# Create the AES cipher in CTR mode
cipher = AES.new(key, AES.MODE_CTR, counter=counter)

# Encrypt the data
enc = cipher.encrypt(data)

# Print the encrypted data
print(enc.hex())

