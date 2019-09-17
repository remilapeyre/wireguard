#!/usr/bin/env python

import argparse
import socket
import logging
import os

# from tkinter import *
# from tkinter.ttk import *

logger = logging.getLogger('wireguard-totp-client')


class WireGuardTOTPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._socket = socket.socket()
        self._f = self._socket.makefile()

    def _send(self, msg: str):
        logger.debug('> %s', msg)
        msg += '\n'
        self._socket.send(msg.encode())
        received = self._f.readline()
        logger.debug('< %s', received)
        status, _, msg = received.strip().partition(' ')
        return status, msg

    def login(self, totp):
        return self._send('login '+totp)

    def logout(self):
        return self._send('logout')

    def status(self):
        return self._send('status')

    def init(self):
        return self._send('init')

    def renew(self):
        return self._send('renew')

    def connect(self):
        self._socket.connect((self.host, self.port))

    def close(self):
        self._socket.close()
        self._socket = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


# def center(root):
#     root.update_idletasks()

#     screen_width = root.winfo_screenwidth()
#     screen_height = root.winfo_screenheight()

#     size = tuple(int(_) for _ in root.geometry().split('+')[0].split('x'))
#     x = screen_width/2 - size[0]/2
#     y = screen_height/2 - size[1]/2
#     root.geometry("+%d+%d" % (x, y))


# class Application(Frame):
#     def __init__(self, master=None):
#         super().__init__(master)
#         master.title('WireGuard TOTP')
#         center(master)
#         self.master = master
#         self.pack()
#         self.create_widgets()

#     def do_login(self):
#         self.master.destroy()

#     def create_widgets(self):
#         self.totp = Entry(self, show="*")
#         self.totp.pack(side="top")
#         self.totp.focus()

#         self.login = Button(self, text="Login", command=self.do_login)
#         self.login.pack(side="bottom")


# root = Tk()
# app = Application(master=root)
# app.mainloop()

def report_failure(title, msg) -> None:
    if msg:
        print('{}: {}'.format(title, msg))
    else:
        print(title)

def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', type=str)
    parser.add_argument('--port', type=int)


    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser('status')

    login = subparsers.add_parser('login')
    login.add_argument('OTP')

    subparsers.add_parser('logout')
    subparsers.add_parser('renew')
    subparsers.add_parser('init')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    args = parser.parse_args()

    logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))

    with WireGuardTOTPClient(args.address, args.port) as client:
        if args.action == 'login':
            status, msg = client.login(args.OTP)
            if status == 'ok':
                print('Logged in until {}'.format(msg))
            else:
                report_failure('Failed to login', msg)

        elif args.action == 'logout':
            status, msg = client.logout()
            if status == 'ok':
                print('Logged out')
            else:
                report_failure('Failed to logged out', msg)

        elif args.action == 'renew':
            status, msg = client.renew()
            if status == 'ok':
                print('Renewed until {}'.format(msg))
            else:
                report_failure('Failed to renew authorisation', msg)

        elif args.action == 'init':
            status, msg = client.init()
            if status == 'ok':
                print('Initialisation successfull: {}'.format(msg))
            else:
                report_failure('Failed to initialise properly', msg)

        elif args.action == 'status':
            status, msg = client.status()
            if status == 'ok':
                print('Status: {}'.format(msg))
            else:
                report_failure('Failed to get status', msg)

        else:
            raise ValueError("Wrong action {!r}".format(args.action))
