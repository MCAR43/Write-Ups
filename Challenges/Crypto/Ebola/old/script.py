#!/usr/bin/env python3
import binascii
from collections import Counter
from math import floor
conv_table = {
	'A':"00",
	'C':"01",
	'G':"10",
	'T':"11"
}

MESSAGE = 'encrypted.bin'
KEYFILE = 'newkey.txt'

def prepKey():
	binary_key = ""
	with open(KEYFILE, 'r') as f:
		seq = f.readlines()[0]
	
	for char in seq.strip('\n'):
		binary_key += conv_table[char]
	
	return binary_key 

def decr(message, key):
	rkey = (key * (floor(len(message) / len(key)))) + key[:len(message) % len(key)]
	decrString = ""
	if len(rkey) == len(message):
		for i in range(len(rkey)):
			xor_byte = int(rkey[i]) ^ int(message[i])
			decrString += str(xor_byte)


	return decrString

def main():
	encr = ""
	key = prepKey()
	with open(MESSAGE, 'rb') as enc:
		byte = enc.read(1)
		while byte:
			bin_byte = str(bin(ord(byte)))[2:]
			bin_byte = bin_byte.rjust(8,'0')
			encr += bin_byte
			byte = enc.read(1)
	
	print(len(encr))
	print(len(prepKey()))
	decrypt = decr(encr,prepKey())
	for i in range(0,len(decrypt), 8):
		print(chr(int(decrypt[i:i+8], 2)), end="")
	

if __name__ == "__main__":
    main()
