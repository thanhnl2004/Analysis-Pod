import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_val(enc_key: str, enc_val: str, iv_val: str) -> str:
    key = enc_key.encode('utf-8')
    
    iv = base64.b64decode(iv_val)
    
    ciphertext = base64.b64decode(enc_val)
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return decrypted_bytes.decode('utf-8')

def main():
    enc_key = ""
    iv_val = "vh+1H1om5UUQyUFQAT5d8w=="
    enc_val = "91ujxNNk0tOpGDlTvTZxGqLQIKVbAiH48sPhBKcsO2trXz91srCv9i8Wi2RXBZwQ+dB3FKBG84EVXXqDxBTHnDi3dIvSqdXDHX+2CyM3YNuMBH+S0uwLIOfn69qgm+caTNaUSUdBlRSrDla/cjHPZYbcIOtokBgnnVRt1hZ2POI="

    
    try:
        decrypted_text = decrypt_val(enc_key, enc_val, iv_val)
        print("Successfully decrypted!")
        print(decrypted_text)
    except Exception as e:
        print(f"Failed to decrypt: {e}")

if __name__ == "__main__":
    main()