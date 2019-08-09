#!/usr/bin/env python3
from string import ascii_lowercase
from collections import Counter
letter_freq = "_ETAONRISHDLFCMUGYPWBVKJXQZ".lower()
freq = {
	"_":"9",
	"a":"179",
	"d":"195",
	"e":"131",
	"g":"230",
	"h":"211",
	"i":"68",
	"k":"136",
	"o":"21",
	"p":"47",
	"q":"41",
	"s":"164",
	"t":"117"
}

dbg = input()


freqCounter = Counter()
encMessage = [] 
with open('encrypted.bin', 'rb') as f:
	byte = f.read(1)
	while byte:
		byte = ord(byte)
		freqCounter[byte] += 1
		encMessage.append(byte)
		byte = f.read(1)

strMessage = ""
inv_map = {v: k for k, v in freq.items()}
print(inv_map)

for char in encMessage:
	strChar = str(char)
	
	try:
		character = inv_map[strChar]
	except KeyError:
		character = "$" 

	if character != "$":
		print(character, end="")
	else:
		if dbg == '1':
			print(character + strChar, end="")
		else:
			print(character, end="")
	
