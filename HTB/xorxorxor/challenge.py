#!/usr/bin/python3
from base64 import b64encode
import os
flag = open('flag.txt', 'r').read().strip().encode()

class XOR:
    def __init__(self):
        self.key = os.urandom(4)
    def encrypt(self, data: bytes) -> bytes:
        xored = b''
        for i in range(len(data)):
            xored += bytes([data[i] ^ self.key[i % len(self.key)]])
        return xored
    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)
    def updateKey(self):
        self.key = os.urandom(4)

def main():
    global flag
    crypto = XOR()
    for i in range(50000):
        crypto.updateKey()
        hexFlag = crypto.encrypt(flag).hex()
        finalFlag = ""
        for i in range(0,len(hexFlag) - 2, 2):
            char = hexFlag[i:i+2]
            try: 
                #print(char, end="_")
                part = bytes.fromhex(char).decode("ASCII")
                finalFlag += part
            except: 
                finalFlag += '_'
        mtch = ["htb", "HTB", "{", "}"]
        if "H" in finalFlag:
            print("Flag (%s) (%d): " % (b64encode(crypto.key).decode('utf-8'), i), end='')
            print(finalFlag)
        else:
            print()

if __name__ == '__main__':
    main()
