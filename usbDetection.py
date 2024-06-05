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


# enables to check whether the file is
# in any of the folders on the drive
# def find_private_key_file(drive, filename="privateKey.txt"):
#     print(f"Searching for {filename} on {drive}:")
#     try:
#         for root, dirs, files in os.walk(drive):
#             if filename in files:
#                 print(f"File {filename} found at: {os.path.join(root, filename)}")
#                 return True
#         print(f"File {filename} is not on the drive")
#     except Exception as e:
#         print(f"Could not search files on {drive}: {e}")
#     return False


#This function is merely for testing purpouses
#Deciphering will occur in another script
def decipher(private_key, aes_nonce):
    pin = "1234"
    pin_key = pin.encode() * 16  # Pad PIN is 16 bytes (AES block size)
    aes_cipher = AES.new(pin_key[:16], AES.MODE_EAX, nonce=aes_nonce)
    decrypted_private_key = aes_cipher.decrypt(private_key)
    print(decrypted_private_key.decode())


drive = detect_new_drive()
key, aes_nonce = get_key_nonce(drive)
decipher(key, aes_nonce)
