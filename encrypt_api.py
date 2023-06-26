# Description: This program will be executed only when we have a new api key
#
# Place the api key in a file called api.txt
#
# Create an api.txt file with the device api key (This is only to encrypted the password and will be removed)
# Run this script and it will create 2 files - apikey.txt and apipass.txt
# It will then delete the api.txt file to keep the key from being exposed on the file system
#
# Requires the cryptography library (pip install cryptography)

from cryptography.fernet import Fernet
import os

### 1. read your password file
with open('api.txt') as f:
    mypwd = ''.join(f.readlines())

### 2. generate key and write it in a file
key = Fernet.generate_key()
f = open("apikey.txt", "wb")
f.write(key)
f.close()

### 3. encrypt the password and write it in a file
refKey = Fernet(key)
mypwdbyt = bytes(mypwd, 'utf-8') # convert into byte
encryptedPWD = refKey.encrypt(mypwdbyt)
f = open("apipass.txt", "wb")
f.write(encryptedPWD)
f.close()
### 4. delete the password file
if os.path.exists("api.txt"):
  os.remove("api.txt")
else:
  print("File is not available")