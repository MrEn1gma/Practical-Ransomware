import idaapi
from base64 import b64decode

start_addr = 0x484398
end_addr = 0x484a98

def Avaddon_decrypt_string(c):
    return str("".join([chr((((i ^ 2) + 4) ^ 0x49) & 0xff) for i in b64decode(c)]))

def Avaddon_find_ciphertext(start_addr, end_addr):
    while(start_addr < end_addr):
        jmp_addr = int(idc.GetDisasm(start_addr)[0xe:], 16)
        size_ciphertext = get_operand_value(jmp_addr, 0)
        ciphertext = ida_bytes.get_bytes(get_operand_value(idc.next_head(jmp_addr), 0), size_ciphertext).decode()
        if(ciphertext not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"):
            decrypted = Avaddon_decrypt_string(ciphertext)
            print("[INFO] Addr: 0x%x | %s | size: 0x%x" % (start_addr, decrypted, size_ciphertext))
            idc.set_cmt(start_addr, "DECRYPTED: %s" % decrypted, 0)
        start_addr = idc.next_head(start_addr)
        
Avaddon_find_ciphertext(start_addr, end_addr)