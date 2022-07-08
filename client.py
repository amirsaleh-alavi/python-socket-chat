import socket, threading, sys

if len(sys.argv) != 3:
    print("Correct usage: script, IP address, port number")
    exit()

def handle_messages(connection: socket.socket):
    '''
        Receive messages sent by the server and display them to user
    '''
    global username
    while True:
        try:
            msg = connection.recv(1024)

            # If there is no message, there is a chance that connection has closed
            # so the connection will be closed and an error will be displayed.
            # If not, it will try to decode message in order to show to user.
            if msg:
                if msg.decode().startswith("yourid"):
                    username = msg.decode()[6:]
                elif msg.decode().startswith("prompt:"):
                    print(msg.decode()[7:])
                else:

                    parsed_message = msg.decode().split(",", 2)
                    sender = parsed_message[0]
                    receiver = parsed_message[1]
                    message = parsed_message[2]

                    if receiver == username:
                        print("Message from %s: %s" % (sender,message))
            else:
                connection.close()
                break

        except Exception as e:
            print(f'Error handling message from server: {e}')
            connection.close()
            break

def client() -> None:
    '''
        Main process that start client connection to the server 
        and handle it's input messages
    '''

    global username

    SERVER_ADDRESS = str(sys.argv[1])
    SERVER_PORT = int(sys.argv[2])

    try:
        username = "null"
        # Instantiate socket and start connection with server
        socket_instance = socket.socket()
        socket_instance.connect((SERVER_ADDRESS, SERVER_PORT))
        # Create a thread in order to handle messages sent by server
        threading.Thread(target=handle_messages, args=[socket_instance]).start()

        print('Connected to chat!')
        print('To send a message, enter "send"')
        print('To exit the program, enter "quit"')

        # Read user's input until it quit from chat and close connection
        while True:
            receiver = "null"

            msg = input()

            if msg == 'quit':
                break
            elif msg == 'send':
                print("Who do you want to send your message to? (enter receivers's username)")
                receiver = input()
                print("Enter your message:")
                msg = input()
            elif msg == 'addfriend':
                receiver = "addfriend"
                print("Who do you want to add as your friend? (enter username)")
                msg = input()

            message_to_send = username + "," + receiver + "," + msg
            # Parse message to utf-8
            socket_instance.send(message_to_send.encode())

        # Close connection with the server
        socket_instance.close()
        sys.exit()

    except Exception as e:
        print(f'Error connecting to server socket {e}')
        socket_instance.close()

if __name__ == "__main__":
    client()
