import socket
import pickle
import ff3_1
import random
pin = 1234
card = "1234567890123456"
credit = 1000000 # 10 Lakh
bill = 100000 # 1 lakh

def total_credit():
    sum = 0
    f = open('data_base.txt','r')
    for i in f:
        tmp = i.split()
        sum = sum + int(tmp[0])
    return sum

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
serverSocket.bind(("127.0.0.1",9090))

serverSocket.listen()

credit_details = []

while(True):

    (clientConnected, clientAddress) = serverSocket.accept()

    print("Accepted a connection request from %s:%s"%(clientAddress[0], clientAddress[1]))
    def bill_limit(message):
        bool1 = int(message) <= bill
        if not bool1:
            print("Bill Limit Reached")
            clientConnected.send(bytes("Bill exceeded 1 Lakhs and Transaction Failed","utf-8"))
            return False
        else:
            return True


    def credit_limit(message):
        bool2=  total_credit() + int(message) <= credit
        if not bool2:
            print("Credit Limit Reached")
            clientConnected.send(bytes("Credit Limt of 10 Lakhs reached and Transaction Failed","utf-8"))
            return False
        else:
            return True
    
    
    # Acknowldegement to sever '''
    message = pickle.loads(clientConnected.recv(1024))
    random.seed(pin)
    K = bytes(str(ff3_1.random_number(16)),'utf-8')
    T = "ABD212A5D4C842"  # tweak string of length 56 (14 pairs of hexadecimal)
    if ff3_1.decrypt_fpe(message[1], T, K) == card and bill_limit(message[0]) and  credit_limit(message[0]):
        with open('data_base.txt', "a") as fil: # Opens the file using 'w' method. See below for list of methods.
            print(message[2])
            fil.write(message[0]+' '+message[2]+'\n')
            fil.close() # Closes file
        clientConnected.send(bytes("Transaction successful","utf-8"))
    else:
        clientConnected.send(bytes("Transaction was not successful wrong credentials","utf-8"))


    clientConnected.send("received".encode())
    print(message)