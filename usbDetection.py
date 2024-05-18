import psutil
import os

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


def list_files(drive):
    print(f"Listing files on {drive}:")
    try:
        for root, dirs, files in os.walk(drive):
            for name in dirs:
                print(os.path.join(root, name))

            for name in files:
                print(os.path.join(root, name))
    except Exception as e:
        print(f"Could not list files on {drive}: {e}")

#straightforward
#enables to check whether the file is on the root folder
#returns the key
def get_key(drive):
    try:
        with open(drive + "privateKey.txt", 'r') as keyFile:
            key = []
            for line in keyFile:
                key.append(line.strip('\n'))
            return key
    except Exception as e:
        print(f"Could not find private key on {drive}: {e}")
    return []

#enables to check whether the file is
#in any of the folders on the drive
def find_private_key_file(drive, filename="privateKey.txt"):
    print(f"Searching for {filename} on {drive}:")
    try:
        for root, dirs, files in os.walk(drive):
            if filename in files:
                print(f"File {filename} found at: {os.path.join(root, filename)}")
                return True
        print(f"File {filename} is not on the drive")
    except Exception as e:
        print(f"Could not search files on {drive}: {e}")
    return False


drive = detect_new_drive()
key = get_key(drive)
print(key)


