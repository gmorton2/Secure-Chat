import socket
import threading
import select
import rsa
import sys
from rsa import key, common
from Crypto.Cipher import AES
import base64, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
import Crypto.Signature.pkcs1_15 
from Crypto.Util.Padding import pad, unpad

listenPort = 1234

# The socket the server uses for listening
listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Associate the listening socket with
# port 1234
listenSock.bind(('', 1234))

# Start listening with a connection backlog queue
# of 100
listenSock.listen(100)

# The user name to socket dictionary
userNameToSockDic = {}

# A map of group names to group member sockets
groupToSockDic = {}

# Map from user names to group names that the user is a member of
userNameToGroupMembershipsDic = {}


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
	
		# Convert the size to the integer
		intSize = int(size)

		# Receive the data
		data = sock.recv(intSize)

		return data
	
	except Exception as e:
		print(str(e))
		return None

usernamePassword = {"a" : "a", "b" : "b", "c" : "c"}
	
def auth(clienComSock):
	flag=False;
	while not flag:
		
		# Get the user name
		userName = recvMsg(clienComSock)
		
		#if(userName==None):
			#print("recvMsg Error in auth function w/userName!")
			#break
			
		# Get the password	
		password = recvMsg(clienComSock)
		
		#if(password==None):
			#print("recvMsg Error in auth function w/password!")
			#break
			
		# change from bytes to string
		userName=userName.decode()
		password=password.decode()
		
		if not userName in usernamePassword:
			sendMsg(clienComSock, "Wrong credentials!")
			print("Wrong credentials")
		elif usernamePassword[userName] == password:
			print("Got user name", userName)
			sendMsg(clienComSock, "Login Successful!")
			flag = True
			break
	return userName
				
def loadPublicKey(userName):
	with open (userName+"_public.pem", "rb") as pub_file:
		contents = pub_file.read()
		pubKey = RSA.importKey(contents)
	userToPubKey[userName] = pubKey	

def getKey(dictionary, value):
	return next((k for k, v in dictionary.items() if v == value), None)
	
def sendEncSymKeyToGroupMembs(socket_group,symKey,userToSock):
	#sends the unecrpyted symmetric key to each user
	for user in socket_group:
			
		#get username(key) from userToSock with sock(value)
		key = getKey(userToSock,user)
				
		#adds any padding if needed to public key for specific user
		cipher = PKCS1_v1_5.new(userToPubKey[key])
				
		# MIG: Added this
		#encrypts the sym key using the users public key
		cipherKeyAndIV = cipher.encrypt(symKey + iv)
		cipherKey = "s".encode()+cipherKeyAndIV
		
		#sends the enc sym key to each user in the group
		#if(sendMsgExpHandler(user,cipherKey)==None):
			#print("sendMsg Error in sendEncSymKeyToGroupMembs!")
			#break		
			
		sendMsg(user, cipherKey)

####################################################
# Extracts a message from the signed message
# verifies the digital signature, and returns
# the original message
# @param msg - the original message on success and None
# on faliure
# |3 byte signature length header|message|signature
###################################################
def extractMsgAndVerifySig(msg, pubKey):
	
	# The return value
	retVal = None
	
	# Get the leading three bytes indicating the
	# signature length
	sigLen = int(msg[:3])
	
	# Get the message
	justMsg = msg[3:len(msg) - sigLen]
	
	# Get the signature
	signature = msg[len(msg) - sigLen:]
	
	# Compute the hash of the message
	hash = SHA256.new(justMsg)
		
	# The veification class
	verifier = Crypto.Signature.pkcs1_15.new(pubKey)
	
	# Verify the signature
	try:
		verifier.verify(hash,signature)
		
		# Save the return message
		retVal = justMsg
		
		print("The signature is valid!");
	# The verification failed
	except ValueError:
		print("Verification failed")
	
	
	return retVal
		
############################################################
# Will be called by the thread that handles a single client
# @param clisock - the client socket
# @param userName - the user name to serve
#############################################################
userToPubKey = {}
BLOCK_SIZE = 16

def serviceTheClient(cliSock, userName, userToSock):
	
	# Keep servicing the client until it disconnects
	while cliSock:
		if flags[userToSock[userName]] == False:
			break
		# Receive the data from the client
		cliData = recvMsg(cliSock)
		
		#if(cliData==None):
			#print("recvMsg Error in serviceTheClient function!")
			#break
		
		msg = cliData
		
		if chr(msg[0]) == "c":
			msg=msg[1:]
			#load private key of server
			with open ("server_private.pem", "rb") as prv_file:
				contents = prv_file.read()
				privKey = RSA.importKey(contents)
			
			cipher = PKCS1_v1_5.new(privKey)
			plainText = cipher.decrypt(msg, 1000)
			plainText=plainText.decode()
			
			#split cmds so each arguemnt can be iterated through
			cmds = plainText.split()
            
			if cmds[0]=="/chatwith":
				socket_group=[]
			
				print("The user sent a group request command: ", msg)
			
				#adds the user's public key who initiates the /chatwith cmd
				loadPublicKey(userName)
				
				#take "/chatwith" off so the names are left
				cmds.pop(0)
				for cmd in cmds:
					#add the socket of the user to the sock list
					#---> need to make sure to add the client sock
					socket_group.append(userToSock[cmd])

                                	# Add all members to the group 
					userNameToGroupMembershipsDic[cmd] = "Cool"
				
					# adds the public key and username pair of all the user names in the cmd
					loadPublicKey(cmd)
			
                        	# Add the current user to the group
				userNameToGroupMembershipsDic[userName] = "Cool"
				socket_group.append(cliSock)
				groupToSockDic["Cool"] = socket_group
			
				#encrypts the symmetric key made by the server with each
				#group memebers public key and sends it to that specific user	
				sendEncSymKeyToGroupMembs(socket_group,symKey,userToSock)
		
		else:
			# Check if the user is a member of any groups
			if userName in userNameToGroupMembershipsDic:

                    		# Get the group of the user
				groupName = userNameToGroupMembershipsDic[userName]

                    		# Get all the sockets in that group
				groupSocks = groupToSockDic[groupName]
			
				# Forward the message to everyone in the group
				for sock in groupSocks:
			
		    			# Don't forward to self
					if cliSock != sock:
						
						#get the public key from the username
						puKey = userToPubKey[userName]
						
						#create a cipher to be used for decrpytion
						cipher = AES.new(symKey, AES.MODE_CBC, iv)
						
						#decrpyts message with the symmetric key and unpads it
						decMsg = unpad(cipher.decrypt(msg),16)
						
						#verifies the signature and ectracts the user's sent message
						decMsg = extractMsgAndVerifySig(decMsg, puKey)
						
						#sends user's message to another person in the group chat
						sendMsg(sock, decMsg)
						
			#prints data to the server
			print("<", userName, "> ",cliData)
		
def genRandomSymmetricKeyAndIV():
	# MIG: modified this
	AES_key_len = 16
	symmetricKey = os.urandom(AES_key_len)
	iv = os.urandom(16)
	return (symmetricKey, iv)

flags={}

# Generate a public/private key pair
private_key = RSA.generate(1024)

# Get the private key
public_key = private_key.publickey()

# The private key bytes to print
privKeyBytes = private_key.exportKey(format='PEM') 

# The public key bytes to print
pubKeyBytes = public_key.exportKey(format='PEM')
 
# Save the private key
with open ("server_private.pem", "wb") as prv_file:
	prv_file.write(privKeyBytes)

# Save the public key
with open ("server_public.pem", "wb") as pub_file:
	pub_file.write(pubKeyBytes)
	
# MIG: Added this
# Generate the key and the IV 
symKey,iv = genRandomSymmetricKeyAndIV()
			
# Server loop
while True:
	
	# Accept the connection
	clienComSock, cliInfo = listenSock.accept()

	print("New client connected: ", cliInfo)
	
	userName = auth(clienComSock)

	# The user name to socket	
	userNameToSockDic[userName] = clienComSock
	
	flags[userNameToSockDic[userName]]=True
	
	# Create a new thread
	cliThread = threading.Thread(target=serviceTheClient, args=(clienComSock,userName,userNameToSockDic,))
	
	# Start the thread
	cliThread.start()
	
