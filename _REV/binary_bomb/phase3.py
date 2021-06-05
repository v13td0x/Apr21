'''str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_{}'

def func1(ch):
	v1 = ord(ch)
	v2 = v1
	ch = v2
	if(ch > 64 and ch <= 90):
		ch -= 13
		if(ch > 64):
			v1 = 0
		else:
			v1 = 26
		ch += v1
	if(ch > 96 and ch < 122):
		ch -= 13
		if(ch > 96):
			v2 = 0
		else:
			v2 = 26
		ch += v2
	return chr(ch)

def func2(ch):
	v1 = ord(ch)
	ch = v1
	if(ch > 32 and ch != 127):
		ch -= 47
		if(ch > 32):
			v1 =0
		else:
			v1 = 94
		ch += v1
	return chr(ch)

new_s = ''
for i in range(len(str)):
	ch = func1(str[i])
	new_s += func2(ch)
print(new_s)
'''

'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_{}'
"?@ABCDEFGHIJK23456789:;<=K}~!"#$%&'()*+pqrstuvwxyz{|_`abcdefgh\0LN"


D0uBl3_Cyc1iC_rO74tI0n_S7r1nGs
"_9~Jb0!=AG!06qfc8'_20uf62%7