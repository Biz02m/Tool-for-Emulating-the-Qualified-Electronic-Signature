from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from GUI.Gui import Gui

if __name__ == "__main__":
    gui = Gui()

    # pin = input("Podaj PIN do zaszyfrowania klucza prywatnego: ")
    # # Generowanie kluczy RSA
    # key_pair = RSA.generate(4096)
    #
    # # Wyświetlanie kluczy
    # print("Klucz prywatny:")
    # klucz = key_pair.export_key()
    # print(klucz.decode())
    # print("\nKlucz publiczny:")
    # publicKey = key_pair.publickey().export_key()
    # with open("public_key.txt", "w") as writer:
    #     writer.write(publicKey.decode())
    # print(publicKey.decode())
    #
    # pin_key = pin.encode() * 16  # Pad PIN to 16 bytes (AES block size)
    # aes_cipher = AES.new(pin_key[:16], AES.MODE_EAX)
    # encrypted_private_key = aes_cipher.encrypt(klucz)
    # print(encrypted_private_key)
    # with open("private_key.txt", "wb") as writer:
    #     writer.write(encrypted_private_key)
    # aes_nonce = aes_cipher.nonce

    #required in another app
    #aes_cipher = AES.new(pin_key[:16], AES.MODE_EAX, nonce = aes_nonce)
    #decrypted_private_key = aes_cipher.decrypt(encrypted_private_key)
    #print(decrypted_private_key.decode())