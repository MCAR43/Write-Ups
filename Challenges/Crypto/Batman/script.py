#!/usr/bin/env python3

with open('finale.txt', 'r') as f:
	msg = f.readlines()[0]

print(msg, end="")
msg = msg.replace('N', '1')
msg = msg.replace('A', '0')
print(msg)
