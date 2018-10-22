import sys
import time
import os
import socket
import traceback
import argparse
import getpass
import gnupg
import io
import typing
from daemonize import Daemonize
from PIL import Image
import cups

CONNECTION_LIMIT = 20
CUPS_CONNECTION = None

PASSPHRASE = None

SUPPORTED_IMAGE_FORMATS = ['BMP', 'GIF', 'ICO', 'JPEG', 'PNG', 'TIFF', 'WebP']

def check_rate_limit(connection_ip):
    '''Checks previous connections and rejects this one if connected too over
    some number of times today.
    Returns True if connection allowed, false if not.

    Delete last line: https://stackoverflow.com/a/10289740
    '''
    #TODO have one variable with the date/time string and use that instead of
    #multiple calls to strftime

    try:
        rate_limit_file = open(connection_ip+".rate", "r+")
    except FileNotFoundError:
        rate_limit_file = open(connection_ip+".rate", "a+")

    #This is really slow, apparently. But we probably don't care much.
    last = ""
    for last in rate_limit_file:
        pass

    if last.split(" ")[0] == time.strftime("%d/%m/%Y"):
        #Check the existing value for today
        if int(last.split(" ")[1]) >= CONNECTION_LIMIT:
            #Return false if we've exceeded the limit
            rate_limit_file.close()
            return False
        else:
            #Increment it
            previous_val = int(last.split(" ")[1])
            rate_limit_file.seek(0, os.SEEK_END)
            pos = rate_limit_file.tell() - 1
            while pos > 0 and rate_limit_file.read(1) != "\n":
                pos -= 1
                rate_limit_file.seek(pos, os.SEEK_SET)

            if pos > 0:
                rate_limit_file.seek(pos, os.SEEK_SET)
                rate_limit_file.truncate()

            rate_limit_file.write("\n"+time.strftime("%d/%m/%Y")+" "+str(previous_val+1))
    elif last.split(" ")[0] != time.strftime("%d/%m/%Y"):
        #Add a new date if it doesnt exist yet.
        rate_limit_file.close()
        rate_limit_file = open(connection_ip+".rate", "a")

        rate_limit_file.writelines(time.strftime("%d/%m/%Y")+" "+str(1)+"\n")

    rate_limit_file.close()

    return True


def write_file(string: str, ip_addr: str, date: str) -> str:
    """
    Wrapper around write_file_binary to handle strings
    :param string: The string to write
    :param ip_addr: The IP of the client
    :param date: Date the message was sent
    :return Filename written to
    """
    data = bytearray(b"------------\n" + ip_addr.encode() + b"\n" + date.encode() + b"\n------------\n")
    data.extend(string.encode())
    data.extend(b"\n------------")
    return write_file_binary(string.encode(), ip_addr, date)


def write_file_binary(data: bytes, ip_addr: str, date: str) -> str:
    """
    Saves the binary data to a file.
    File name is: <ip_addrv4>_<d/m/Y>
    :param data: The data to write
    :param ip_addr: The IP of the client
    :param date: Date the message was sent
    :return Filename written to
    """
    folder = "logs/"
    filename = folder + str(ip_addr) + "_" + str(date)
    with open(filename, "wb+") as message_file:
        message_file.write(data)
    return filename

def print_file(filename):
    '''Sends the file to the printer '''
    if CUPS_CONNECTION is None:
        return

    default = CUPS_CONNECTION.getDefault()
    if default == None:
        raise IOError("No default printer")

    return CUPS_CONNECTION.printFile(default, filename, filename, dict())

def parse_string(string):
    '''Parses the printable bytes with an attempt to find
    one of the special strings we can handle'''

    gpg = gnupg.GPG()

    if "-----BEGIN PGP MESSAGE----" in string[:30]:
        message_decrypted = gpg.decrypt(string, passphrase=PASSPHRASE)

        return str(message_decrypted)

    return string

def handle_image(data: bytes) -> typing.Union[None, bytes]:
    """
    Attempts to parse an image using Pillow
    :param data: Raw image binary data
    :return: Image data in JPEG format if the data was handled, None if not
    """
    try:
        # One of these two calls will raise an IOError if the data isn't an image
        im = Image.open(io.BytesIO(data))
        im.load()

        if im.format not in SUPPORTED_IMAGE_FORMATS:
            raise IOError

        output = io.BytesIO()
        im.save(output, format='jpeg')

        return output.getvalue()
    except IOError:
        return None


def await_connections():
    """
    Await connections from the outside
    and take all actions necessary to print
    our content
    """
    #Uncomment the below to accept non-localhost connections
    #IP = "0.0.0.0"
    IP = "127.0.0.1"
    PORT = 7878

    buffer_size = 1024

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((IP, PORT))

    try:
        while True:
            sock.listen(1)
            conn, addr = sock.accept()

            if check_rate_limit(addr[0]):
                data = conn.recv(buffer_size)

                image_data = handle_image(data)
                if image_data is not None:
                    filename = write_file_binary(image_data, addr[0], time.strftime("%d-%m-%Y-%H-%M%p"))
                else:
                    try:
                        received_string = received_bytes.decode("utf-8")
                    except UnicodeDecodeError as err:
                        print("Error decoding received bytes %r (%s)" % (received_bytes, err))
                        conn.close()
                        continue
                    filename = write_file(parse_string(received_string), addr[0], time.strftime("%d-%m-%Y-%H-%M%p"))

                print_file(filename)

                conn.send(b"OK")
                conn.close()
            else:

                conn.close()
    except (KeyboardInterrupt, SystemExit):
        sock.close()


if __name__ == "__main__":

    pid = "/tmp/postoffice.pid"
    daemon = False
    cups = False
    PASSPHRASE = getpass.getpass('Password for GPG: ')

    parser = argparse.ArgumentParser(description='A one way telegram machine!')
    parser.add_argument('-d', dest='daemon', action='store_true',
                        help='Daemonize the process')
    parser.add_argument('-P', '--no-printer', dest='printer',
                        action='store_false',
                        help="Don't send files to the printer")
    args = parser.parse_args(sys.argv[1:])

    if args.printer:
        try:
            import cups
            CUPS_CONNECTION = cups.Connection()
        except (ImportError, RuntimeError) as e:
            print('Error initialising CUPS:', file=sys.stderr)
            print(traceback.format_exc(), file=sys.stderr)
            print("Cups connection will be mocked.", file=sys.stderr)

    if args.daemon:
        print("Daemonizing....")
        daemon = Daemonize(app="PostOffice", pid=pid, action=await_connections)
        daemon.start()
    else:
        await_connections()
