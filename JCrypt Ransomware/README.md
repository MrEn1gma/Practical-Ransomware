# JCrypt (MafiaWare666) Ransomware
- Decryptor is avaiable (just replace target encrypted file and password bytes).

## NOTE
- This ransomware used AES CBC Encryption with key and iv are generated from salt and password encryption which were calcuated by HMAC-SHA1 Algorthim, also using padding PKCS7 in AES.
- The salt will written in the first 32 bytes of encrypted file after implemented HMAC-SHA1 Algorthim. So that I can take them to decrypt.
