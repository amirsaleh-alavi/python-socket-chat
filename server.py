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
if len(sys.argv) != 2:
    print("Correct usage: script, port number")
    exit()

# Global variable that mantain client's connections
connections = []

# Global variables for paths
script_path = os.path.dirname(__file__)                     # Path of the running python script
db_path = script_path + "/db"                               # db path
usersinfo_path = script_path + "/db/usersinfo"              # usersinfo path
messages_path = script_path + "/db/messages"                # messages path
userslist_path = script_path + "/db/userslist.txt"          # Userslist file path

# Creating required directories and files
Path(db_path).mkdir(parents=True, exist_ok=True)            # Creating db directory if necessary
Path(usersinfo_path).mkdir(parents=True, exist_ok=True)     # Creating usersinfo directory if necessary
Path(messages_path).mkdir(parents=True, exist_ok=True)      # Creating messages directory
Path(userslist_path).touch(exist_ok=True)                   # Touch userslist file

# encrypt function
def encrypt(plaintext: bytes, public_key):
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

# Importe private key from given file path
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

# Importe public and private keys from given file path
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

# Checking existance of private and public keys
serverpubkey_path = script_path + "/db/serverpubkey.txt"    # Public key file path
serverprvkey_path = script_path + "/db/serverprvkey.txt"    # Private key file path

# Deciding weather to generate keys or import them from files
if not os.path.exists(serverprvkey_path):
    # Generating a pair of private and public keys and store them to given paths
    private_key, public_key, private_bytes, public_bytes = generate_and_store_asymetric_keys(serverprvkey_path, serverpubkey_path)
else:
    # import private and public keys from files
    private_key, private_bytes = import_private_key(serverprvkey_path)
    public_key, public_bytes = import_public_key(serverpubkey_path)

# Get user connection in order to keep receiving their messages and
# sent to others users/connections.
def handle_user_connection(connection: socket.socket, address: str) -> None:

    # A non stopping loop that handles receiving messages from clients
    while True:
        try:
            # Get client message
            received_message = connection.recv(1024000)

            # If no message is received, there is a chance that connection has ended
            # so in this case, we need to close connection and remove it from connections list.
            if received_message:
                # Parse received message
                parsed_message = received_message.split(b',nextfield,', 3)
                sender = parsed_message[0]
                receiver = parsed_message[1]
                message_body = parsed_message[2]
                message_signature = parsed_message[3]

                # Define sender and receiver friend list file paths
                sender_friends_file_path = script_path + "/db/usersinfo/" + sender.decode() + ".friends.txt"
                receiver_friends_file_path = script_path + "/db/usersinfo/" + receiver.decode() + ".friends.txt"

                # Import sender's public key
                sender_public_key_path = script_path + "/db/usersinfo/" + sender.decode() + ".public_key.txt"
                sender_public_key, senders_public_bytes = import_public_key(sender_public_key_path)

                if receiver.decode() == "encaddfriend":
                    # Opening the userslist file and put every username into indexed list
                    userslist_path = script_path + "/db/userslist.txt"
                    userslist_operation = open(userslist_path, "r+")
                    userslist = [line for line in userslist_operation.readlines()]

                    # Decrypt the message and check signature
                    message_body = decrypt(message_body, private_key)
                    if verify(message_signature, message_body, sender_public_key):
                        if (message_body.decode()+"\n") in userslist:
                            f = open(sender_friends_file_path,"a+")
                            f.write(message_body.decode() + "\n")
                            f.close()

                            new_friend_public_key_path = script_path + "/db/usersinfo/" + message_body.decode() + ".public_key.txt"
                            new_friend_public_key, new_friend_public_bytes = import_public_key(new_friend_public_key_path)

                            sender = "encnewfriend".encode()
                            receiver = message_body
                            
                            encrypted_new_friend_public_bytes = [encrypt(new_friend_public_bytes[0:180], sender_public_key),encrypt(new_friend_public_bytes[180:370], sender_public_key),encrypt(new_friend_public_bytes[370:], sender_public_key)]
                            
                            message_body = encrypted_new_friend_public_bytes[0] + encrypted_new_friend_public_bytes[1] + encrypted_new_friend_public_bytes[2]

                            message_signature = sign(new_friend_public_bytes[0:180],private_key) + sign(new_friend_public_bytes[180:370],private_key) + sign(new_friend_public_bytes[370:],private_key)

                            sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                            connection.send(sending_message)

                            print("Sending %s's public key to a client" % (receiver.decode()))
                        else:
                            receiver = sender
                            sender = "encprompt".encode()
                            message_body = "No such user exists in database.".encode()
                            message_signature = sign(message_body, private_key)
                            message_body = encrypt(message_body,sender_public_key)

                            sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                            connection.send(sending_message)
                    else:
                        print("Signature doesn't match with message")
                else:
                    if os.path.exists(sender_friends_file_path):
                        h = open(sender_friends_file_path, "r+")
                        friends = [line for line in h.readlines()]
                    else:
                        friends = []

                    if (receiver.decode() + "\n") in friends:
                        broadcast(received_message, connection)
                    else:
                        message_body = "encprompt:%s is not in your friends list and you may not send message to them."  % receiver
                        message_body = message_body.encode()
                        receiver = sender
                        sender = "encprompt".encode()
                        message_body = encrypt(message_body,sender_public_key)
                        message_signature = sign(message_body,private_key)

                        sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                        connection.send(sending_message)
            else:
                # Close connection if no message was sent
                remove_connection(connection)
                break

        except Exception as e:
            print(f'Error to handle user connection: {e}')
            remove_connection(connection)
            break

# Broadcast message to all users connected to the server
def broadcast(message, connection: socket.socket) -> None:

    # Iterate on connections in order to send message to all client's connected
    for client_conn in connections:
        # Check if isn't the connection of who's send
        if client_conn != connection:
            try:
                # Sending message to client connection
                client_conn.send(message)

            # if it fails, there is a chance of socket has died
            except Exception as e:
                print('Error broadcasting message: {e}')
                remove_connection(client_conn)

# Define a function that removes specified connection from connections list
def remove_connection(conn: socket.socket) -> None:

    # Check if connection exists on connections list
    if conn in connections:
        # Close socket connection and remove connection from connections list
        conn.close()
        connections.remove(conn)

# Main process that receive client's connections and start a new thread
def server() -> None:

    # Get the listening port from the first argument of the script
    LISTENING_PORT = int(sys.argv[1])
    
    try:
        # Create server and specifying that it can only handle 100 connections by time!
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.bind(('', LISTENING_PORT))
        socket_instance.listen(100)

        print('Server running!')
        
        # Start a not stopping loop that listens for new connections
        while True:

            # Accept client connection
            socket_connection, address = socket_instance.accept()
            
            # Create an initialmsg containing the public key of the server and sending it to the client
            sender = "serverpubkey".encode()
            receiver = "null".encode()
            message_body = public_bytes
            message_signature = "nosignature".encode()
            sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
            socket_connection.send(sending_message)

            # Define a function to ask client wheather to sign in or sign up
            def SignInUp():
                # Create a not stopping loop that only stops if the break line is reached
                while True:
                    # Create message block and asking the client what they want to do
                    sender = "prompt".encode()
                    receiver = "null".encode()
                    message_body = "SignIn (I) or SignUp (U)?".encode()
                    message_signature = "nosignature".encode()
                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_connection.send(sending_message)

                    # Receiving the response of the client and decrypt it with server public key
                    received_message = socket_connection.recv(1024000)
                    parsed_message = received_message.split(b',nextfield,', 3)
                    sender = parsed_message[0]
                    receiver = parsed_message[1]
                    message_body = parsed_message[2]
                    message_signature = parsed_message[3]

                    message_body_clear = decrypt(message_body,private_key)

                    # If the answer is not U or I, start the loop again and ask the client again
                    if message_body_clear.decode() in ("U", "I"):
                        return message_body_clear.decode()
                    else:
                        continue

            # Define a function to complete the sign up process
            def SignUp():
                # Create message block
                receiver = "null".encode()
                message_signature = "nosignature".encode()

                # Opening the userslist file and put every username into indexed list
                userslist_path = script_path + "/db/userslist.txt"
                userslist_operation = open(userslist_path, "r+")
                userslist = [line for line in userslist_operation.readlines()]

                # Ask the client to enter the username
                sender = "prompt".encode()
                message_body = "Enter a username of your choice:".encode()
                sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                socket_connection.send(sending_message)
                
                # Receiving the response of the client and decrypt it with server public key
                received_message = socket_connection.recv(1024000)
                parsed_message = received_message.split(b',nextfield,', 3)
                sender = parsed_message[0]
                receiver = parsed_message[1]
                message_body = parsed_message[2]
                message_signature = parsed_message[3]
                
                message_body_clear = decrypt(message_body,private_key)
                requested_user_id = message_body_clear.decode()

                # Search in all userslist entries for the username to see if it is already taken
                if not (requested_user_id + "\n") in userslist:
                    # Asking the client to enter a password
                    sender = "prompt".encode()

                    message_body = "You may use this username.".encode()
                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_connection.send(sending_message)

                    message_body = "Enter your desired password:".encode()
                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_connection.send(sending_message)

                    # Receiving the response of the client and decrypt it with server public key
                    received_message = (socket_connection.recv(1024000))
                    parsed_message = received_message.split(b',nextfield,', 3)
                    sender = parsed_message[0]
                    receiver = parsed_message[1]
                    message_body = parsed_message[2]
                    message_signature = parsed_message[3]

                    message_body_clear = decrypt(message_body,private_key)
                    requested_password = message_body_clear.decode()

                    # Sending a message to the client to generate a pair of public and private keys and receiving the public key
                    sender = "generateyourkey".encode()

                    message_body = requested_user_id.encode()
                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_connection.send(sending_message)

                    received_public_bytes = socket_connection.recv(1024000)
                    
                    # Define userslist file path and appending the new user to the file
                    userslist_path = script_path + "/db/userslist.txt"
                    f = open(userslist_path,"a+")
                    f.write(requested_user_id + "\n")
                    f.close()

                    # Define username file path and storing the new username to the file
                    username_path = script_path + "/db/usersinfo/" + requested_user_id + ".username.txt"
                    f = open(username_path,"a+")
                    f.write(requested_user_id)
                    f.close()

                    # Define user's public key' file path and storing the public key to the file
                    user_public_key_path = script_path + "/db/usersinfo/" + requested_user_id + ".public_key.txt"
                    f = open(user_public_key_path,"a+")
                    f.write(received_public_bytes.decode())
                    f.close()

                    # Define user's password file path and storing the password to the file
                    pass_path = script_path + "/db/usersinfo/" + requested_user_id + ".pass.txt"
                    f = open(pass_path,"a+")
                    f.write(requested_password)
                    f.close()

                    # Define users's friends file path and creating an empty file for them
                    user_friends_path = script_path + "/db/usersinfo/" + requested_user_id + ".friends.txt"
                    Path(user_friends_path).touch(exist_ok=True)

                    # Define user's messages directory path and creating an empty directory for them
                    user_message_path = script_path + "/db/messages/" + requested_user_id
                    Path(user_message_path).mkdir(parents=True, exist_ok=True)

                    # Sending a message to the user saying that they've successfully registered and return True 
                    sender = "prompt".encode()
                    message_body = "You have been registered successfully. Now please log in.".encode()

                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_connection.send(sending_message)
                    return True
                else:
                    # Sending a message to the user saying that the chosen username is already taken and return False
                    sender = "prompt".encode()
                    message_body = "This username is taken. Try another one.".encode()

                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_connection.send(sending_message)
                    return False

            # Define a function to complete the sign in process
            def SignIn():

                # Create message block
                receiver = "null".encode()
                message_signature = "nosignature".encode()

                # Opening the userslist file and put every username into indexed list
                userslist_path = script_path + "/db/userslist.txt"
                userslist_operation = open(userslist_path, "r+")
                userslist = [line for line in userslist_operation.readlines()]

                # Ask the client to enter the username
                sender = "prompt".encode()
                message_body = "Enter your username:".encode()

                sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                socket_connection.send(sending_message)

                # Receiving the response of the client and decrypt it with server public key
                received_message = socket_connection.recv(1024000)
                parsed_message = received_message.split(b',nextfield,', 3)
                sender = parsed_message[0]
                receiver = parsed_message[1]
                message_body = parsed_message[2]
                message_signature = parsed_message[3]

                message_body_clear = decrypt(message_body,private_key)
                username = message_body_clear.decode()

                # Asking the client to enter the password
                sender = "prompt".encode()
                message_body = "Enter your passowrd:".encode()

                sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                socket_connection.send(sending_message)

                # Receiving the response of the client and decrypt it with server public key
                received_message = socket_connection.recv(1024000)
                parsed_message = received_message.split(b',nextfield,', 3)
                sender = parsed_message[0]
                receiver = parsed_message[1]
                message_body = parsed_message[2]
                message_signature = parsed_message[3]

                message_body_clear = decrypt(message_body,private_key)
                password = message_body_clear.decode()

                # Search in all userslist entries for the username to see if it exists
                if username+"\n" in userslist:
                    # Define the passowrd file and read the password from it
                    correctpass_path = script_path + "/db/usersinfo/"+username+".pass.txt"
                    with open(correctpass_path, 'r') as k:
                        correctpass = k.read().rstrip()

                    # Determine if the entered passoword matches the password on file
                    if password == correctpass:
                        # Get user's public key to encrypt messages from now on
                        signedin_user_public_key_path = script_path + "/db/usersinfo/" + username + ".public_key.txt"
                        signedin_user_public_key, signedin_user_public_bytes = import_public_key(signedin_user_public_key_path)

                        # Inform the user that they have logged in successfully
                        sender = "encprompt".encode()
                        receiver = username.encode()

                        message_body = "Logged in successfully!\nTo send a message enter 'send'\nTo add someone as your friend enter 'addfriend'\n".encode()
                        message_signature = sign(message_body,private_key)
                        message_body = encrypt(message_body,signedin_user_public_key)

                        sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                        socket_connection.send(sending_message)

                        # Send the client's username to them to store it
                        sender = "encyourid".encode()
                        message_body = username.encode()
                        message_signature = sign(message_body,private_key)
                        message_body = encrypt(message_body, signedin_user_public_key)

                        sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                        socket_connection.send(sending_message)

                        #Print log on screen
                        print("User %s logged in" % (username))

                        # Return True
                        return True
                    else:
                        # Since the password doesn't match the password on file, don't login and return False
                        sender = "prompt".encode()
                        receiver = "null".encode()
                        message_body = "Username or Password in incorrect. Try again!".encode()
                        message_signature = "nosignature".encode()

                        sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                        socket_connection.send(sending_message)
                        return False
                else:
                    # Since the username doesn't exist, don't login and return False
                    sender = "prompt".encode()
                    receiver = "null".encode()
                    message_body = "Username or Password in incorrect. Try again!".encode()
                    message_signature = "nosignature".encode()
                    
                    sending_message = sender + b',nextfield,' + receiver + b',nextfield,' + message_body + b',nextfield,' + message_signature
                    socket_connection.send(sending_message)
                    return False

            # Call the SignInUp function and proceed the algorithm
            operation = SignInUp()
            if operation == "U":
                while True:
                    signupsuccess = SignUp()
                    if signupsuccess == True:
                        break
                while True:
                    signinsuccess = SignIn()
                    if signinsuccess == True:
                        break
            elif operation == "I":
                while True:
                    signinsuccess = SignIn()
                    if signinsuccess == True:
                        break

            # Add client connection to connections list
            connections.append(socket_connection)

            # Start a new thread to handle client connection and receive it's messages
            # in order to send to others connections
            threading.Thread(target=handle_user_connection, args=[socket_connection, address]).start()

    except Exception as e:
        print(f'An error has occurred when instancing socket: {e}')
    finally:
        # In case of any problem we clean all connections and close the server connection
        if len(connections) > 0:
            for conn in connections:
                remove_connection(conn)

        socket_instance.close()
        server()

if __name__ == "__main__":
    server()