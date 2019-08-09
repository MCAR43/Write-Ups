#!/usr/bin/env python

#QK<_>.<<<<H>5<<{_<I>>ck>'>>b0<<<<<<<<<I<<<<T>>f>>>>>>_>>>>>>}<.<.<<<<3<<<<<<<<u<<t_>>a<<<<<<<<<<B>>>>>>>>>>>>>>t>5<<<I>>>_>>>>>a<<<<<<a>>>>>>d<<<<y>>>r
#QK_.H5{_Ick'b0ITf_}..3ut_aBt5I_aadyr

with open('keywalk', 'r') as f:
	keywalk = f.readlines()[-1]


lenwalk = ((keywalk.replace('<','')).replace('>','')).replace('\n','')
flag = ['-' for i in range(len(lenwalk))]
ind=0
for char in keywalk.strip('\n'):
	if char == '<':
		ind-=1	
		pass
	elif char == '>':
		ind+=1
		pass
	else:
		flag.insert(ind, char)
		ind+=1
	
	print "char is: " + char
	print "ind is: " + str(ind)
	print "flag is: " + str(flag)
	print
	

for char in flag:
	print(char),
