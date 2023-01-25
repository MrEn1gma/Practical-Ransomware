from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from hashlib import pbkdf2_hmac

ransom_extension = ".CRYPT"							    # RANSOM EXTENSION
org_filename = "CRACK.txt"	                            # ORGINAL FILE 
enc_filename = org_filename + ransom_extension
data = open(enc_filename, "rb").read()
pwd = b"c29oZmdvc2FlaWgzOTQ4NzU2YWdubHN"
salt_ = data[:32]
print("Salt: ", salt_)
ciphertext = data[32:]
dk = pbkdf2_hmac('sha1', pwd, salt_, 50000, dklen=32+16)
AES_key = dk[:32]
AES_iv = dk[32:]
aes = AES.new(AES_key, AES.MODE_CBC, AES_iv)
out = aes.decrypt(ciphertext)
out = unpad(out, AES.block_size)
#print(out)
open(org_filename, "wb").write(out)
print("OK")