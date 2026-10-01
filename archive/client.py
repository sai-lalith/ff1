import socket
import pickle
import ff3_1
import random
from datetime import datetime


clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

clientSocket.connect(("127.0.0.1",9090))

amount = input("Enter the amount: ")
ccn = str(input("Enter your credit card number: "))
pin = int(input("Enter your pin: "))
T = "ABD212A5D4C842"  # tweak string of length 56 (14 pairs of hexadecimal)
random.seed(pin)
K = bytes(str(ff3_1.random_number(16)),'utf-8')
now = datetime.now()
time = now.strftime("%Y-%m-%d %H:%M:%S")
l = [amount,ff3_1.encrypt_fpe(ccn,T,K),time]
#for i in range(len(l)):
 #   clientSocket.send(l[i].encode())
datasent = pickle.dumps(l)
clientSocket.send(datasent)  
    
print(l)

dataFromServer = clientSocket.recv(1024)

print(dataFromServer.decode())
