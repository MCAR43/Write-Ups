#!/usr/bin/env python3
from string import ascii_lowercase
from collections import Counter
letter_freq = "_ETAONRISHDLFCMUGYPWBVKJXQZ".lower()
freq = {
	"O":"233",
	"W":"84",
	"3":"188",
	"4":"178",
	"0":"158",
	"}":"81",
	"\n":"218",
	" ":"9",
	"a":"179",
	"b":"72",
	"c":"38",
	"d":"195",
	"e":"131",
	"f":"79",
	"g":"230",
	"h":"211",
	"i":"68",
	"j":"",
	"k":"136",
	"l":"238",
	"m":"216",
	"n":"110",
	"o":"21",
	"p":"47",
	"q":"41",
	"r":"93",
	"s":"164",
	"t":"117",
	"u":"234",
	"v":"129",
	"w":"103",
	"x":"",
	"y":"31",
	"z":"133",
	"T":"243",
	"B":"77",
	"H":"155",
	"E":"7",
	".":"240",
	",":"35",
	"S":"74",
	"C":"214",
	"R":"249",
	"{":"172",
	"1":"191",
	"9":"40",
	"7":"171",
	"6":"145",
	"2":"223",
	"W":"18",
	"O":"237",
	"N":"174",
	"(":"80",
	"V":"96",
	"D":"183",
	")":"220",
	"Y":"194",
	"F":"119",
	"P":"203",
	"L":"92",
	"-":"215"
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
		character = "_" 

	if character != "_":
		print(character, end="")
	else:
		if dbg == '1':
			print(character + strChar, end="")
		else:
			print(character, end="")
	
