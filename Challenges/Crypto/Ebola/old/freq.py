#!/usr/bin/env python3
from string import ascii_lowercase
from collections import Counter
letter_freq = "_ETAONRISHDLFCMUGYPWBVKJXQZ".lower()
freq = {
	"_":"",
	"a":"",
	"b":"",
	"c":"",
	"d":"",
	"e":"",
	"f":"",
	"g":"",
	"h":"",
	"i":"",
	"j":"",
	"k":"",
	"l":"",
	"m":"",
	"n":"",
	"o":"",
	"p":"",
	"q":"",
	"r":"",
	"s":"",
	"t":"",
	"u":"",
	"v":"",
	"w":"",
	"x":"",
	"y":"",
	"z":""
}


freqCounter = Counter()
encMessage = [] 
with open('encrypted.bin', 'rb') as f:
	byte = f.read(1)
	while byte:
		byte = ord(byte)
		freqCounter[byte] += 1
		encMessage.append(byte)
		byte = f.read(1)

for i, char in enumerate(freqCounter.most_common(len(letter_freq))):
	freq[letter_freq[i]] = char[0]

print(freqCounter.most_common(27))

strMessage = ""
inv_map = {v: k for k, v in freq.items()}
for char in encMessage:
	try:
		strMessage += inv_map[char]
		print(inv_map[char], end="")
	except KeyError:
		strMessage += "$"
		print("$", end="")

bigrams = Counter()
for i in range(0, len(strMessage) - 2, 1):
	tri = ""
	for char in strMessage[i:i+2]:
		tri += char

	bigrams[tri] += 1



trigrams = Counter()
for i in range(0, len(strMessage) - 3, 1):
	tri = ""
	for char in strMessage[i:i+3]:
		tri += char

	trigrams[tri] += 1


quadgrams = Counter()
for i in range(0, len(strMessage) - 4, 1):
	tri = ""
	for char in strMessage[i:i+4]:
		tri += char

	quadgrams[tri] += 1


digraph = Counter()
for word in strMessage.split('_'):
	if len(word) == 2:
		digraph[word] += 1

print("Digraphs:")
print(digraph.most_common(30))
print("Bigrams: ")
print(bigrams.most_common(30))
print()
print("Trigrams: ")
print(trigrams.most_common(30))
print()
print("Quadgrams: ")
print(quadgrams.most_common(30))
print()
print("Freq")
print(freq)
