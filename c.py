import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto import Random
import base64
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import binascii
import Crypto.Signature.pkcs1_15 
from Crypto.Util.Padding import pad, unpad

###############################################
# Returns the signature of the message
# @param msg - the message
# @return - the message with the signature
# The message begins with the three bytes 
# indicating the length of the signature
# that is appended to the end of the message
# The format is
# |3-byte signature length||Message||Signature|
###############################################
def addSignature(msg, privKey):

	# Compute the hash of the message
	hash = SHA256.new(msg.encode())
	
	# The signer class
	signer = Crypto.Signature.pkcs1_15.new(privKey)
	
	# The signature
	signature = signer.sign(hash)
	
	# Get the length of the signature
	sigLen = len(signature)

	# Convert the length to string and to bytes
	sigLenBytes = str(sigLen).encode()

	# Prepad with the three bytes
	while len(sigLenBytes) < 3:
		
		sigLenBytes = b'0' + sigLenBytes 

	return sigLenBytes + msg.encode() + signature	

#############################
# The server port and IP
serverIP = "127.0.0.1"
serverPort = 1234

# Create a TCP socket that uses IPv4 address
cliSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
cliSock.connect((serverIP, serverPort))

###########################################################
# The function to handle the message of the specified format
# @param sock - the socket to receive the message from
# @returns the message without the header
############################################################
def recvMsg(sock):
	data=None
	try:
		# The size
		size = sock.recv(3)
	
		#print("Got size: ", size)
	
		# Convert the size to the integer
		intSize = int(size)

		# Receive the data
		data = sock.recv(intSize)

		return data
	
	except Exception as e:
		print(str(e))
		return None
		

################################################
# Puts the message into the formatted form
# and sends it over the socket
# @param sock - the socket to send the message
# @param msg - the message
################################################
def sendMsg(sock, msg):

	sMsg = None
	
	if(isinstance(msg,str)):
		# Get the message length
		msgLen = str(len(msg))
	
		# Keep prepending 0's until we get a header of 3	
		while len(msgLen) < 3:
			msgLen = "0" + msgLen
	
		# Encode the message into bytes
		msgLen = msgLen.encode()
	
		# Put together a message
		sMsg = msgLen + msg.encode()
		
	elif(isinstance(msg,bytes)):
		# Get the message length
		msgLen = str(len(msg))
	
		# Keep prepending 0's until we get a header of 3	
		while len(msgLen) < 3:
			msgLen = "0" + msgLen
	
		# Put together a message
		sMsg = msgLen.encode() + msg
	else:
		print("Don't know the type ", type(msg))
	
	# Send the message
	sock.sendall(sMsg)

def sendMsgExpHandler(sock,msg):
	
	try:
		sendMsg(sock, msg)
		return 1
		
	except Exception as e:
		print(str(e))
		return None
		
		
BLOCK_SIZE = 16
iv = Random.new().read(AES.block_size)
###################################################
# Handles the user input
# @param mySock - the socket on which to handle the input
###################################################
def inputHandlerThread(mySock, username):

	while True:
		msg = input("")
		cmd = msg.split()
		
		if cmd[0] == "/chatwith":
			#adds any padding if needed to public key for specific user
			cipher = PKCS1_v1_5.new(pubKey)
				
			#encrypts the sym key using the users public key
			msg = cipher.encrypt(msg.encode())
			msg = "c".encode()+msg
		else:
			#adds username to meesage to show up on client side
			msg = "g<"+username+"> "+msg
			
			#if msg == ("g<"+username+">" +" exit"):
				# Hang up the client
				#sendMsg(cliSock, "User: "+username+" is OFFLINE")
				#mySock.close()
				#exit()

			#loads in the user's private key that is sending the message
			with open (username+"_private.pem", "rb") as prv_file:
				contents = prv_file.read()
				privKey = RSA.importKey(contents)
			
			#adds signature to the message to be sent
			msg = addSignature(msg, privKey)
			
			#creates cipher to encrypt message using the symmetric key
			cipher = AES.new(symKey, AES.MODE_CBC, iv)
			
			#pads the message to be a multiple of 16 so that encryption can occur
			msg = pad(msg,16)
			
			#encryts the message that is to be sent
			msg = cipher.encrypt(msg)

			#print(len(msg))
		#if(sendMsgExpHandler(cliSock,msg)==None):
			#print("sendMsg Error in inputHandlerThread!")
			#break
			
		sendMsg(cliSock, msg)

def auth(cliSock):

	while True:
		username = input("Enter your username: ")
			
		sendMsg(cliSock, username)
		
		password = input("Enter your password: ")
		
		sendMsg(cliSock, password)
		
		msg=recvMsg(cliSock)
		
		if(msg==None):
			print("recvMsg Error in auth function!")
			break

		print(msg.decode())
		if msg.decode() == "Login Successful!":
			
			# Generate a public/private key pair
			private_key = RSA.generate(1024)

			# Get the private key
			public_key = private_key.publickey()

			# The private key bytes to print
			privKeyBytes = private_key.exportKey(format='PEM') 

			# The public key bytes to print
			pubKeyBytes = public_key.exportKey(format='PEM') 

			# Save the private key
			with open (username+"_private.pem", "wb") as prv_file:
    				prv_file.write(privKeyBytes)

			# Save the public key
			with open (username+"_public.pem", "wb") as pub_file:
    				pub_file.write(pubKeyBytes)
			
			inputterThread = threading.Thread(target=inputHandlerThread, args=(cliSock,username,))
			inputterThread.start()
			arrivingMessageListener = threading.Thread(target=handleArrivingMessages, args=(cliSock,username))
			arrivingMessageListener.start()
			break
symKey = None
################################################
# Listens for new messages
#@param mySock - the socket on which to handle the output
################################################
def handleArrivingMessages(mySock, username):
	global symKey
	global iv
	while True:
		msg=recvMsg(cliSock)
		
		if(msg==None):
			print("recvMsg Error in handleArrivingMessages!")
			break
			
		if chr(msg[0]) == "s":
			msg=msg[1:]
			#load private key of server
			with open (username+"_private.pem", "rb") as prv_file:
				contents = prv_file.read()
				privKey = RSA.importKey(contents)
			
			cipher = PKCS1_v1_5.new(privKey)
			msg = cipher.decrypt(msg, 1000)
			# MIG: Added this
			symKey = msg[0:16]
			iv = msg[16:]
		else:
			msg=msg.decode()
			msg=msg[1:]
			
		print(msg)

#added this because they werent being called
with open ("server_public.pem", "rb") as pub_file:
		contents = pub_file.read()
		pubKey = RSA.importKey(contents)
			
auth(cliSock)
