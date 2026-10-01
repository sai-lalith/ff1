#%%
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
from bitstring import BitArray

block = 16
T = "ABD212A5D4C842"  # tweak string of length 56 (14 pairs of hexadecimal)

# %%
# AEScipher class
class AEScipher:
    def __init__(self, key, plain_text):  
        self.key = key
        self.plain_text = plain_text
    def getKey(self, key):
        self.key = key
    def getPlainText(self, plain_text):
        self.plain_text = plain_text
    def encrypt(self):
        cipher = AES.new(self.key, AES.MODE_ECB)
        cipher_text = cipher.encrypt(pad(self.plain_text,block))
        return cipher_text 
    def decrypt(self, cipher_text):
        cipher = AES.new(self.key, AES.MODE_ECB)
          # Setup cipher
        original_data = cipher.decrypt(unpad(cipher_text,block))
        return original_data
#%%

# Functions

def num_radix(X):
    x = 0
    for i in range(len(X)):# length of plaintext = 16
        x = x*radix + int(X[i])
    return int(x)

def string_radix(x,m): # v=8
    #m = len(x)
    X = [0 for i in range(m)]
    x = int(x)
    for i in range(m):
        X[m-1-i] = x % radix
        x = math.floor(x/radix) # floor value
    k = ""
    for i in range(m):    
        k = k + str(X[i])
    return k# returns the plaintext
  

def num(X):
    x = 0
    for i in range(0,len(X)):
        x = 2*x + int(X[i])
    return int(x)

          
def reverse(X):
    Y=X
    Y=list(Y)
    X=list(X)
    k = ""
    for i in range(0,len(X)):
        Y[i] = X[len(X)-1-i]
        k = k + Y[i]
    return k

def reverse_bytes(X):
    bytes_size = math.ceil(len(X)/8)
    r = [[] for i in range(bytes_size)]    
    count = 0
    for i in range(len(X)):
        if i % 8 == 0 and i != 0:
            count = count + 1        
        r[count].append(X[i])
    a = ""
    for i in range(len(r)):
        for j in range(8):
            a = a + r[len(r)-1-i][j]
    return a

def xor(a, b):
    y = int(a,2) ^ int(b,2)
    return '{0:b}'.format(y)

def random_number(N):
	minimum = pow(10, N-1)
	maximum = pow(10, N) - 1
	return random.randint(minimum, maximum)


# %%
# good tested method to convert bits and bytes in python 
# would be to access the stack and play with raw bits but it's out of scope
# we use the bitstring to do bidding for us
# converting bits to bytes example:
# BitArray('0b1011').tobytes()
# converting bytes to bits example:
# a = BitArray(b'\x00\xd2')
# using a.bin to get the bit string
# Encryption
radix = 10
minlen = 6
maxlen = 56
n = 16
u = math.ceil(n/2) # u = 8
v = n-u

def encrypt_fpe(X, T, K):
    aes = []
    T_l = T[0:8]
    T_r = T[8:16] + T[7] + str(0)  
    A = X[0:8] # first 8 digits of plaintext(x)
    B = X[8:16]
    for i in range(8):
        if i%2==0:
            m = u # u = 8
            W = T_r
        else:
            m = v # v = 8
            W = T_l
        # converting hex to bin
        P = xor(bin(int(W,16))[2:], ('{:032b}'.format(i))) + '{:0192b}'.format((num_radix(reverse(str(B)))))    
        aes.append(AEScipher(BitArray('0b'+reverse_bytes(BitArray(K).bin)).tobytes(),BitArray('0b'+reverse_bytes(P)).tobytes()))
        CIPH = aes[i].encrypt()
        S = reverse_bytes(BitArray(CIPH).bin)
        y = num(S)
        c = (num_radix(reverse(A))+y) % (radix**m)
        C = reverse(string_radix(c,m))
        A = B
        B = C
    return A+B

# %%
def decrypt_fpe(Y,T,K):
    A = Y[0:8] # first 8 digits of plaintext(x)
    B = Y[8:16]
    T_l = T[0:8]
    T_r = T[8:16] + T[7] + str(0) 
    aes = []
    for j in range(8):
        i = 7 - j
        if i%2==0:
            m = u # u = 8
            W = T_r
        else:
            m = v # v = 8
            W = T_l
        # converting hex to bin
        P = xor(bin(int(W,16))[2:], ('{:032b}'.format(i))) + '{:0192b}'.format((num_radix(reverse(str(A)))))    
        aes.append(AEScipher(BitArray('0b'+reverse_bytes(BitArray(K).bin)).tobytes(),BitArray('0b'+reverse_bytes(P)).tobytes()))
        CIPH = aes[j].encrypt()
        S = reverse_bytes(BitArray(CIPH).bin)
        y = num(S)
        c = (num_radix(reverse(B))-y) % (radix**m)
        C = reverse(string_radix(c,m))
        B = A
        A = C
    return A+B
'''
T = "ABD212A5D4C842"  # tweak string of length 56 (14 pairs of hexadecimal)
X =  "4088498645809206"  # plaintext
K = b'73#43$95%$+A7+)5'
c = encrypt_fpe(X,T,K)
p = decrypt_fpe(c,T,K)
print(c,p)
print(p == X)
import random
random.seed(127659212841)
passed  = 0
failed = 0
for i in range(1000):
    K = bytes(str(random_number(16)),'utf-8')
    X = str(random_number(16))
    c = encrypt_fpe(X,T,K)
    p = decrypt_fpe(c,T,K)
    if(p == X):
        passed += 1
    else:
        failed += 1
print(passed)
print(failed)
'''