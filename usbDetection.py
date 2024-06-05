import psutil
import os
from Crypto.Cipher import AES


def get_current_drives():
    return [disk.device for disk in psutil.disk_partitions()]


def detect_new_drive():
    print("insert drive:")
    initial_drives = get_current_drives()
    while True:
        current_drives = get_current_drives()
        new_drives = [drive for drive in current_drives if drive not in initial_drives]

        if new_drives:
            print(f'New drive detected: {new_drives[0]}')
            return new_drives[0]

# enables to check whether the file is on the root folder
# returns the key and the nonce value which is required for deciphering
# the driver should not be plugged in beforehand
def get_key_nonce(drive, filename="privateKey.txt"):
    try:
        with open(drive + filename, 'rb') as keyFile:
            aes_nonce = keyFile.read(16)
            key = keyFile.read()
            return key, aes_nonce
    except Exception as e:
        print(f"Error: {drive}: {e}")
    return []

#This function is merely for testing purpouses
#Deciphering will occur in another script
def decipher(private_key, aes_nonce, pin):
    pin_key = pin.encode() * 16  # Pad PIN is 16 bytes (AES block size)
    aes_cipher = AES.new(pin_key[:16], AES.MODE_EAX, nonce=aes_nonce)
    decrypted_private_key = aes_cipher.decrypt(private_key)
    return decrypted_private_key.decode()


drive = detect_new_drive()
key, aes_nonce = get_key_nonce(drive)
deciphered_key = decipher(key, aes_nonce, "1234")
