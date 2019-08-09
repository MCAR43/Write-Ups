#!/usr/bin/env python3
from table import keys 
chars = []
counter = 0
inv_map = {v: k for k, v in keys.items()}
special = {
	"1":"!",
	"2":"@",
	"3":"#",
	"4":"$",
	"5":"%",
	"6":"^",
	"7":"&",
	"8":"*",
	"9":"(",
	"0":")",
	",":"<",
	".":">",
	"/":"?",
	";":":",
	"\'":"\"",
	"[":"{",
	"]":"}"
}
with open('new.txt', 'r') as f:
	for line in f.readlines():
		chars.append(line.strip('\n'))
	
	
for hid_addr in chars:
	if False:
		print("Mod: %s" % str(hid_addr[:2]), end=" - ")
		print("Key: %s" % str(hid_addr[2:]), end=" - ")
		print("Orig: %s" % str(hid_addr))

	mod = int(hid_addr[:2], 16)
	val = hid_addr[2:].replace(':','')
	hexval = int(val[2:4], 16)
	#print(int(val[2:4], 16))
	try:
		character = inv_map[hexval]
	except KeyError:
		character = ""
		pass

	try:
		modval = inv_map[mod]	
	except KeyError:
		modval = ""
		pass
	'''
	character=character.lower()
	if (modval == "LSHIFT" or modval == "RSHIFT"):
		if character in special.keys():
			character = special[character]
		else:
			character = character.upper()
	'''
	if character is not "":
		print(character, end="")

