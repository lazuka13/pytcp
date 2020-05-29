import click

from pytcp.controller import Controller


def client(controller):
    print("client")
    socket = controller.socket()
    socket.bind("10.0.0.10", 30000)
    socket.connect("10.0.0.11", 40000)

    while True:
        text = input()
        socket.send(text.encode("utf-8"))
        out = socket.recv()
        print(out)


def server(controller):
    print("server")
    socket = controller.socket()
    socket.bind("10.0.0.11", 40000)
    socket.listen()

    connection_socket = socket.accept()

    while True:
        data = connection_socket.recv()
        connection_socket.send(reversed(data))


@click.command()
@click.option("-r", "--run", help="run in selected mode")
def main(run):
    controller = Controller()
    if run == "client":
        client(controller)
    else:
        server(controller)


if __name__ == "__main__":
    main()
