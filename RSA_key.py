from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


if __name__ == "__main__":
    pin = input("Podaj PIN do zaszyfrowania klucza prywatnego: ")
    # Generowanie kluczy RSA
    key_pair = RSA.generate(4096)

    # Wyświetlanie kluczy
    print("Klucz prywatny:")
    klucz = key_pair.export_key()
    print(klucz.decode())
    print("\nKlucz publiczny:")
    print(key_pair.publickey().export_key().decode())

    pin_key = pin.encode() * 16  # Pad PIN to 16 bytes (AES block size)
    aes_cipher = AES.new(pin_key[:16], AES.MODE_EAX)
    encrypted_private_key = aes_cipher.encrypt(klucz)
    print(encrypted_private_key)
    aes_nonce = aes_cipher.nonce

    aes_cipher = AES.new(pin_key[:16], AES.MODE_EAX, nonce = aes_nonce)
    decrypted_private_key = aes_cipher.decrypt(encrypted_private_key)
    print(decrypted_private_key.decode())