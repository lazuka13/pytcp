from pytcp.controller import Controller

if __name__ == '__main__':
    controller = Controller()

    socket = controller.socket()
    socket.bind("127.0.0.1", 8080)

    socket.listen()

    controller.stop()
