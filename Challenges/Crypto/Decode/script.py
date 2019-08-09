#!/usr/bin/env python3
def parseFile(infile):
	bytelist = ""
	with open(infile, 'rb') as f:
		byte = f.read(1)
		while byte:
			if byte is not '\n':
				bytelist += (str(bin(ord(byte)))[2:].ljust(8,'0'))
			byte = f.read(1)

	return bytelist

def main(infile, ofile):
	infile_bytes = parseFile(infile)
	key_bytes = parseFile('key.txt')
	rounded = len(infile_bytes) // len(key_bytes)
	remainer = len(infile_bytes) % len(key_bytes)
	key_bytes = (key_bytes * rounded) + key_bytes[:remainer]
	new=""
	print(len(key_bytes))
	print(len(infile_bytes))
	
	for i in range(len(key_bytes)):
		new+= str(int(key_bytes[i],2) ^ int(infile_bytes[i],2))
	
	for i in range(0,len(new), 8):
		print(chr(int(new[i:i+8], 2)),end="")
	


if __name__ == "__main__":
	infile="Decode.txt"
	ofile="decr.txt"
	main(infile, ofile)
