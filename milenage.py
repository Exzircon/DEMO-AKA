'''
	Author: Group \x01
	---
	This file contains the f1 -> f5 functions for MILENAGE and some helper functions
	to eliminate some duplicate code and improve readability. This file does not include
	functions to generate RAND, K, SQN, AMF, and OP and they will need to be supplemented
	\n\n
	Creating a single milenage() function would improve performance as some of the values
	used are the same in all funcitons. f2 and f5 are both derrived from OUT2 aswell.
	---
	The functions have all been tested against the KATs described in 3GPP TS 35.208
'''


'''
	List of Symbols:
	= 			The Assignment operator
	^ / *			The bitwise exclusive-OR operation.
	||			The concatenation of the two operands. (+ should also work)
	E[x]k		The Result of applying a block cipher encryption to the input value x using the key k
	rot(x,r) 	The result of cyclically rotating the 128-bit value x by r bit positions towards the most significant bit.
	X[i]		the ith bit in the variable X.

	List of Variables:
	AK		a 48-bit anonymity key that is the output of either of f5 and f5*.
	AMF		a 16-bit authentication managment field that is the input to f1 and f1*.
	c1, c2, c3, c4, c5		128-bit constants, which are XORed onto intermediate variables
	CK		a 128-bit confidentiality key that is the output of f3
	IK		a 128-bit integrity key that is the output of f4
	IN1		a 128-bit valye constructed from SQN and AMF that is used in the conputation of f1 and f1*
	K		a 128-bit subscriber key that is the input to f1, f1*, f2, f3, f4, f5, and f5*
	MAC-A	a 64-bit network authentication code that is the output of f1
	MAC-S	a 64-bit resynchronisation authentication code that is the output of f1*
	OP		a 128-bit Operator Variant Algorithm Configuration Field that is a component of f1, f1*, f2, f3, f4, f5 and f5*
	OPc		a 128-bit value derived from OP and K and used within the computation of the functions
	OUT1, OUT2, OUT3, OUT4, OUT5		128-bit computed values from which the outputs of f1, f1*, f2, f3, f4, f5 and f5* are obtained
	r1, r2, r3, r4, r5		integers in the range 0-127 inclusive, which defines the amounts by which intermediate varables are cyclically rotated. Always divisible by 8
	RAND	a 128-bit random challenge that is an input to f1, f1*, f2, f3, f4, f5, and f5*
	RES		a 64-bit signed response that is the output of f2
	SQN		a 48-bit sequence number that is an input to f1 or f1*
	TEMP	a	128-bit value used in the computations of the functions
'''

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def xor(*args: bytes):
	'''
	Takes in any number of bytes objects, all of which must be of same length, 
	and performs an xor operation on them, returning a single bytes object.
	'''
	assert(len(args) > 0), "xor must get at least 1 argument"
	if len(args) == 1:
		return args[0]
	for i in range(len(args)):
		if len(args[i]) != len(args[0]):
			raise ValueError
	byte_arr: bytearray = bytearray(len(args[0]))
	for arg in args:
		for i in range(len(arg)):
			byte_arr[i] = byte_arr[i] ^ arg[i]
	return bytes(byte_arr)

def rot(x: bytes|bytearray, r: int, right: bool = False) -> bytes:
	'''
	x: Bytes to rotate, can be of any length
	r: How many BITS to rotate, must be divisible by 8
	right: Wheter to rotate the bits left or right, default left
	'''
	assert(r % 8 == 0), "rotation amount (r) must be divisible by 8"

	rot_amount : int = int(r/8)
	bytearr: bytearray = bytearray(x)
	if right:
		for _ in range(rot_amount):
			bytearr.insert(0, bytearr.pop(-1))
	else:
		for _ in range(rot_amount):
			bytearr.append(bytearr.pop(0))
	return bytes(bytearr)

def Ek(key: bytes, m: bytes) -> bytes:
	'''
	Encrypts input m using a block chiper using the input key, returns encrypted block in bytes
	'''
	assert(len(m) == 16), "m must be 128 bits long or 16 bytes"
	cipher = Cipher(algorithms.AES(key), modes.ECB())
	encryptor = cipher.encryptor()
	ct = encryptor.update(m) + encryptor.finalize()
	return ct

def f1(K: bytes, RAND: bytes, SQN: bytes, AMF: bytes, OPc: bytes):	#Returns MAC-A (64-bits)
	'''
	K: 128-bit subscriber key \n
	RAND: 128-bit random challenge \n
	SQN: 48-bit sequence number \n
	AMF: 16-bit authentication managment field \n
	---
	returns MAC-A: 64-bit network authentication code
	'''
	#Define constants
	r1: int = 64
	c1: bytearray = bytearray(16)

	#Compute OPc and TEMP as described in 3GPP TS 35.206
	#OPc: bytes = xor(OP, Ek(K, OP)) 		#OPc = OP ⊕ E[OP]k
	TEMP : bytes = Ek(K, xor(RAND, OPc)) 	#TEMP = E[RAND ⊕ OPC]k
	
	#Step by step computation of OUT1 as described in 3GPP TS 35.206
	#OUT1 = E[TEMP ⊕ rot(IN1 ⊕ OPC, r1) ⊕ c1]K ⊕ OPC
	IN1 : bytes = SQN + AMF + SQN + AMF
	OUT1 : bytes = xor(OPc, IN1)
	OUT1 : bytes = rot(OUT1, r1)
	OUT1 : bytes = xor(OUT1, TEMP, c1)
	OUT1 : bytes = Ek(K, OUT1)
	OUT1 : bytes = xor(OPc, OUT1)

	return OUT1[:8] #f1 is defined as the first 64bits (8bytes) of OUT1, f1* is the remaining 64bits
	
def f2(K: bytes, RAND: bytes, OPc: bytes):	#Returns RES (64-bits)
	'''
	K: 128-bit subscriber key \n
	RAND: 128-bit random challenge \n
	---
	returns RES: 64-bit signed response
	'''
	#Define constants
	r2: int = 0
	c2: bytearray = bytearray(16)
	c2[15] = 1

	#Compute OPc and TEMP as described in 3GPP TS 35.206
	#OPc: bytes = xor(OP, Ek(K, OP)) 		#OPc = OP ⊕ E[OP]k
	TEMP : bytes = Ek(K, xor(RAND, OPc)) 	#TEMP = E[RAND ⊕ OPC]k

	#Step by step computation of OUT1 as described in 3GPP TS 35.206
	#OUT2 = E[rot(TEMP ⊕ OPC, r2) ⊕ c2]K ⊕ OPC
	OUT2 : bytes = xor(TEMP, OPc)
	OUT2 : bytes = rot(OUT2, r2)
	OUT2 : bytes = xor(OUT2, c2)
	OUT2 : bytes = Ek(K, OUT2)
	OUT2 : bytes = xor(OUT2, OPc)
	return OUT2[8:] #f2 is defined as the last 64bits (8bytes) of OUT2, f5 is defined as the first 48 bits of OUT2
	
def f3(K: bytes, RAND: bytes, OPc: bytes):	#Returns CK (128-bits)
	'''
	K: 128-bit subscriber key \n
	RAND: 128-bit random challenge \n
	---
	returns CK: 128-bit confidentiality key
	'''
	#Define constants
	r3: int = 32
	c3: bytearray = bytearray(16)
	c3[15] = 2

	#Compute OPc and TEMP as described in 3GPP TS 35.206
	#OPc: bytes = xor(OP, Ek(K, OP)) 		#OPc = OP ⊕ E[OP]k
	TEMP : bytes = Ek(K, xor(RAND, OPc)) 	#TEMP = E[RAND ⊕ OPC]k

	#OUT3, OUT4, and OUT5 are all computed in the same way as OUT2, except using their appropreate r's and c's
	#OUT3 can be computed in one line like this
	OUT3 : bytes = xor(Ek(K, xor(rot(xor(TEMP, OPc), r3), c3)), OPc)	#OUT3 = E[rot(TEMP ⊕ OPC, r3) ⊕ c3]K ⊕ OPC
	return OUT3 #f3 is defined as all 128 bits of OUT3

def f4(K: bytes, RAND: bytes, OPc: bytes):	#Returns IK (128-bits)
	'''
	K: 128-bit subscriber key \n
	RAND: 128-bit random challenge \n
	---
	returns IK: 128-bit integrity key
	'''
	#Define constants
	r4: int = 64
	c4: bytearray = bytearray(16)
	c4[15] = 4

	#Compute OPc and TEMP as described in 3GPP TS 35.206
	#OPc: bytes = xor(OP, Ek(K, OP)) 		#OPc = OP ⊕ E[OP]k
	TEMP : bytes = Ek(K, xor(RAND, OPc)) 	#TEMP = E[RAND ⊕ OPC]k
	
	#OUT3, OUT4, and OUT5 are all computed in the same way as OUT2, except using their appropreate r's and c's
	#OUT4 can be computed in one line like this
	OUT4 : bytes = xor(Ek(K, xor(rot(xor(TEMP, OPc), r4), c4)), OPc)	#OUT4 = E[rot(TEMP ⊕ OPC, r4) ⊕ c4]K ⊕ OPC
	return OUT4 #f4 is defined as all 128 bits of OUT4

def f5(K: bytes, RAND: bytes, OPc: bytes):	#Returns AK (48-bits)
	'''
	K: 128-bit subscriber key \n
	RAND: 128-bit random challenge \n
	---
	returns AK: 48-bit anonymity key
	'''
	r2: int = 0
	c2: bytearray = bytearray(16)
	c2[15] = 1

	#Compute OPc and TEMP as described in 3GPP TS 35.206
	#OPc: bytes = xor(OP, Ek(K, OP)) 		#OPc = OP ⊕ E[OP]k
	TEMP : bytes = Ek(K, xor(RAND, OPc)) 	#TEMP = E[RAND ⊕ OPC]k

	#OUT2 = E[rot(TEMP ⊕ OPC, r2) ⊕ c2]K ⊕ OPC
	OUT2 : bytes = xor(Ek(K, xor(rot(xor(TEMP, OPc), r2), c2)), OPc)
	return OUT2[:6] #f5 is defined as the first 48bits (8bytes) of OUT2, f2 is defined as the last 64bits of OUT2


