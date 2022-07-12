#!/usr/bin/env pytohn3

# Copyright (c) , Inc. and its affiliates.
#----------------------------------------------------------------
# Created by    : Amir Saleh Alavi (sms_alavinekoo@yahoo.com)
# Created Date  : 12/07/2022
# Version = 2.0
'''
This is a simple python implementation of a chat program that
supoorts encryption and verification of messages in an end to end
manner.
'''

import socket, threading, sys, os
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Exiting the script because the user has not given the right args
if len(sys.argv) != 3:
    print("Correct usage: script, IP address, port number")
    exit()

# Global variables for paths
script_path = os.path.dirname(__file__)
db_path = script_path + "/db"

# Creating required directories and files
Path(db_path).mkdir(parents=True, exist_ok=True)

def encrypt(plaintext: bytes, public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# decrypt function
def decrypt(ciphertext: bytes, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# sign function
def sign(plaintext: bytes, private_key):
    signature = private_key.sign(
        plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# verify function
def verify(signature: bytes, plaintext: bytes, public_key):
    try:
        public_key.verify(
            signature,
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Define a function to generate and return a pair of public and private keys and store them in the given file
def generate_and_store_asymetric_keys(private_key_path: str, public_key_path: str):
    # Generating a pair of private and public keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    # Extracting the actual bytes of the keys
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Saving the keys to given file paths
    with open(private_key_path, "w+") as f:
        f.write(private_bytes.decode())
    with open(public_key_path, "w+") as f:
        f.write(public_bytes.decode())
    return private_key, public_key, private_bytes, public_bytes

# Import private key from given file path
def import_private_key(private_key_path):
    # Import the private key from given file
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    # Extracting the actual bytes of the key
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key, private_bytes

# Import public key from given file path
def import_public_key(public_key_path):
    # Import public keys from given file paths
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
    # Extracting the actual bytes of the key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key, public_bytes

# Export public key to the given file path
def export_public_key(public_bytes,public_key_path):
    with open(public_key_path, "w+") as f:
        f.write(public_bytes.decode())

def load_public_key(public_bytes):
    public_key = serialization.load_pem_public_key(
        public_bytes,
    )
    return public_key

# Receive messages sent by the server and display them to user
def handle_messages(connection: socket.socket):

    global username
    global program
    global server_public_key
    global server_public_bytes
    global private_key
    global private_bytes
    global public_key
    global public_bytes

    while True:
        if program == "exit":
            print("Exiting...")
            break
        try:
            received_message = connection.recv(1024000)

            # If there is no message, there is a chance that connection has closed
            # so the connection will be closed and an error will be displayed.
            # If not, it will try to decode message in order to show to user.
            if received_message:
                # Parse received message
                parsed_message = received_message.split(b',nextfield,', 3)
                sender = parsed_message[0]
                receiver = parsed_message[1]
                message_body = parsed_message[2]
                message_signature = parsed_message[3]

                if sender.decode() == "prompt":
                    print(message_body.decode())
                elif sender.decode() == "generateyourkey":
                    # variables for paths
                    user_path = script_path + "/db/"+ message_body.decode()
                    mypubkey_path = user_path + "/mypubkey.txt"
                    myprvkey_path = user_path + "/myprvkey.txt"

                    # Creating required directories and files
                    Path(user_path).mkdir(parents=True, exist_ok=True)

                    private_key, public_key, private_bytes, public_bytes = generate_and_store_asymetric_keys(myprvkey_path,mypubkey_path)

                    connection.send(public_bytes)

                elif sender.decode() == "encprompt":
                    username = receiver.decode()
                    user_path = script_path + "/db/"+ username
                    mypubkey_path = user_path + "/mypubkey.txt"
                    myprvkey_path = user_path + "/myprvkey.txt"
                    private_key, private_bytes = import_private_key(myprvkey_path)
                    message_body = decrypt(message_body, private_key)
                    if verify(message_signature,message_body,server_public_key):
                        print(message_body.decode())
                    else:
                        print("Received message signature does not match.")
                elif sender.decode() == "encyourid":
                    username = receiver.decode()
                elif sender.decode() == "encnewfriend":
                    user_path = script_path + "/db/"+ username
                    new_friend_public_bytes_path = user_path + "/" + receiver.decode() + ".public_key.txt"

                    decrypted_new_friend_public_bytes = [decrypt(message_body[0:256], private_key), decrypt(message_body[256:512], private_key), decrypt(message_body[512:768], private_key)]

                    message_body = decrypted_new_friend_public_bytes[0] + decrypted_new_friend_public_bytes[1] + decrypted_new_friend_public_bytes[2]
                    
                    if verify(message_signature[0:256],message_body[0:180],server_public_key) and verify(message_signature[256:512],message_body[180:370],server_public_key) and verify(message_signature[512:768],message_body[370:],server_public_key):

                        export_public_key(message_body,new_friend_public_bytes_path)
                        print("Successfully added.")
                    else:
                        print("Signature doesn't match.")
                else:
                    if receiver.decode() == username:
                        sender_public_key_path = user_path + "/" + sender.decode() + ".public_key.txt"
                        if os.path.exists(sender_public_key_path):
                            sender_public_key, sender_public_bytes = import_public_key(sender_public_key_path)
                            message_body = decrypt(message_body,private_key)
                            if verify(message_signature,message_body,sender_public_key):
                                print("Message from %s: %s" % (sender.decode(),message_body.decode()))
                            else:
                                print("Received signature doesn't match.")
                        else:
                            print("%s sent you a message, but you don't have their public key to confirm their message." % (sender.decode()))
                            message_body = decrypt(message_body,private_key)
                            print("Message from %s: %s" % (sender.decode(),message_body.decode()))
                            print("ATTENTION: YOU CAN'T KNOW FOR SURE THAT %s SENT THIS MESSAGE!" % (sender.decode()))
            else:
                connection.close()
                break

        except Exception as e:
            print(f'Error handling message from server: {e}')
            connection.close()
            break

# Main process that start client connection to the server and handle it's input messages
def client() -> None:

    global username
    global program
    global server_public_key
    global server_public_bytes
    global private_key
    global private_bytes
    global public_key
    global public_bytes

    username = "null"
    program = "running"

    SERVER_ADDRESS = str(sys.argv[1])
    SERVER_PORT = int(sys.argv[2])

    try:
        
        # Instantiate socket and start connection with server
        socket_instance = socket.socket()
        socket_instance.connect((SERVER_ADDRESS, SERVER_PORT))

        # Get server message (server's public key)
        received_message = socket_instance.recv(1024000)

        # Parse received message
        parsed_message = received_message.split(b',nextfield,', 3)
        sender = parsed_message[0]
        receiver = parsed_message[1]
        message_body = parsed_message[2]
        message_signature = parsed_message[3]

        # Get server public bytes and create public key object from it
        server_public_bytes = message_body
        server_public_key = load_public_key(server_public_bytes)

        print('Connected to chat!')

        # Create a thread in order to handle messages sent by server
        t = threading.Thread(target=handle_messages, args=[socket_instance])
        t.start()

        # Read user's input until it quit from chat and close connection
        while True:
            message_body = False

            sender = username.encode()
            receiver = "null".encode()
            message_body = input().encode()
            message_signature = "nosignature".encode()

            if message_body:

                #if message_body.decode() == "quit":
                #    break
                if message_body.decode() == "send":
                    print("Who do you want to send your message to? (enter receivers's username)")
                    sender = username.encode()
                    receiver = input().encode()

                    user_path = script_path + "/db/"+ username
                    receiver_public_key_path = user_path + "/" + receiver.decode() + ".public_key.txt"
                    if os.path.exists(receiver_public_key_path):
                        receiver_public_key, receiver_public_bytes = import_public_key(receiver_public_key_path)
                        print("Enter your message:")
                        message_body = input().encode()
                        
                        # variables for paths
                        messages_directory_path = user_path + "/messages"
                        messages_file_path = messages_directory_path + "/" + receiver.decode() + ".txt"

                        # Creating required directories and files
                        Path(messages_directory_path).mkdir(parents=True, exist_ok=True)
                        Path(messages_file_path).touch(exist_ok=True)

                        now = datetime.now()

                        with open(messages_file_path, 'a+') as g:
                            g.write('%s - %s sent a message to %s: %s\n' % (now,sender.decode(),receiver.decode(),message_body.decode()))

                        message_signature = sign(message_body,private_key)
                        message_body = encrypt(message_body,receiver_public_key)

                        sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature

                        socket_instance.send(sending_message)
                    else:
                        print("Public key not found.")
                elif message_body.decode() == "addfriend":
                    print("Who do you want to add as your friend? (enter username)")

                    message_body = input().encode()
                    sender = username.encode()
                    receiver = "encaddfriend".encode()
                    message_signature = sign(message_body,private_key)
                    message_body = encrypt(message_body,server_public_key)

                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_instance.send(sending_message)
                else:
                    sender = username.encode()

                    if not username == "null":
                        message_signature = sign(message_body,private_key)

                    message_body = encrypt(message_body, server_public_key)

                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_instance.send(sending_message)

        # Close connection with the server
        socket_instance.close()
        program = "exit"

    except Exception as e:
        print(f'Error connecting to server socket {e}')
        socket_instance.close()

if __name__ == "__main__":
    client()