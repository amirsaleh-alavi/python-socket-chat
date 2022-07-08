import socket, threading, sys

if len(sys.argv) != 2:
    print("Correct usage: script, port number")
    exit()

# Global variable that mantain client's connections
connections = []

def handle_user_connection(connection: socket.socket, address: str) -> None:
    '''
        Get user connection in order to keep receiving their messages and
        sent to others users/connections.
    '''
    while True:
        try:
            # Get client message
            msg = connection.recv(1024).decode()

            # If no message is received, there is a chance that connection has ended
            # so in this case, we need to close connection and remove it from connections list.
            if msg:
                broadcast(msg, connection)

            # Close connection if no message was sent
            else:
                remove_connection(connection)
                break

        except Exception as e:
            print(f'Error to handle user connection: {e}')
            remove_connection(connection)
            break

def broadcast(message: str, connection: socket.socket) -> None:
    '''
        Broadcast message to all users connected to the server
    '''

    # Iterate on connections in order to send message to all client's connected
    for client_conn in connections:
        # Check if isn't the connection of who's send
        if client_conn != connection:
            try:
                # Sending message to client connection
                client_conn.send(message.encode())

            # if it fails, there is a chance of socket has died
            except Exception as e:
                print('Error broadcasting message: {e}')
                remove_connection(client_conn)


def remove_connection(conn: socket.socket) -> None:
    '''
        Remove specified connection from connections list
    '''

    # Check if connection exists on connections list
    if conn in connections:
        # Close socket connection and remove connection from connections list
        conn.close()
        connections.remove(conn)


def server() -> None:
    '''
        Main process that receive client's connections and start a new thread
        to handle their messages
    '''

    LISTENING_PORT = int(sys.argv[1])
    
    try:
        # Create server and specifying that it can only handle 4 connections by time!
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.bind(('', LISTENING_PORT))
        socket_instance.listen(100)

        print('Server running!')
        
        while True:

            # Accept client connection
            socket_connection, address = socket_instance.accept()

            def SignInUp():
                while True:
                    socket_connection.send("prompt:SignIn (I), or SighUp (U)?".encode())
                    answer = socket_connection.recv(16).decode()
                    answer = answer[10:]
                    if answer in ("U", "I"):
                        return answer
                        break
                    else:
                        continue

            operation = SignInUp()

            def SignUp():

                userslist_path = "/root/db/userslist.txt"
                userslist_operation = open(userslist_path, "r+")
                userslist = [line for line in userslist_operation.readlines()]

                socket_connection.send("prompt:Enter a username of your choice:".encode())
                requesteduserid = (socket_connection.recv(32)).decode()
                requesteduserid = requesteduserid[10:]
                if not requesteduserid in userslist:
                    socket_connection.send("prompt:You may use this username.".encode())
                    socket_connection.send("prompt:Enter your desired password:".encode())
                    requestedpassword = (socket_connection.recv(32)).decode()
                    requestedpassword = requestedpassword[10:]
                    
                    userslistpath = "/root/db/userslist.txt"
                    f = open(userslistpath,"a+")
                    f.write(requesteduserid + "\n")
                    f.close()

                    usernamepath = "/root/db/usersinfo/"+requesteduserid+".username.txt"
                    f = open(usernamepath,"a+")
                    f.write(requesteduserid)
                    f.close()

                    passpath = "/root/db/usersinfo/"+requesteduserid+".pass.txt"
                    f = open(passpath,"a+")
                    f.write(requestedpassword)
                    f.close()

                    socket_connection.send("prompt:You have been registered successfully. Now please log in.".encode())
                    return True
                else:
                    socket_connection.send("prompt:This username is taken, try another one.".encode())
                    return False

            def SignIn():

                userslist_path = "/root/db/userslist.txt"
                userslist_operation = open(userslist_path, "r+")
                userslist = [line for line in userslist_operation.readlines()]

                socket_connection.send("prompt:Enter your username:".encode())
                username = (socket_connection.recv(32)).decode()
                username = username[10:]
                socket_connection.send("prompt:Enter your passowrd:".encode())
                password = (socket_connection.recv(32)).decode()
                password = password[10:]

                if username+"\n" in userslist:
                    correctpasspath = "/root/db/usersinfo/"+username+".pass.txt"
                    with open(correctpasspath, 'r') as key:
                        correctpass = key.read().rstrip()

                    if password == correctpass:
                        socket_connection.send("prompt:Logged in successfully!".encode())
                        yourid = "yourid" + username
                        print("sending messge:")
                        print(yourid)
                        socket_connection.send(yourid.encode())
                        return True
                    else:
                        socket_connection.send("prompt:Username or Password in incorrect. Try again!".encode())
                        return False
                else:
                    socket_connection.send("prompt:Username or Password in incorrect. Try again!".encode())
                    return False


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

if __name__ == "__main__":
    server()