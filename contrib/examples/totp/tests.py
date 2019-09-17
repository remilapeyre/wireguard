import time

import io
import contextlib
import requests
import ipaddress
import pyotp
from datetime import datetime, timedelta
import sqlite3
import os
import socket
import threading
import time
import unittest
import wireguard_totp
from ipaddress import IPv4Address, IPv4Network
from wireguard_totp import Status

from unittest import TestCase
from unittest.mock import patch, MagicMock


def requireEnvVars(*args):
    vars = ', '.join(map(repr, args))
    def wrapper(cls):
        return unittest.skipIf(
            any(var not in os.environ for var in args),
            f"Define {vars} to run {cls.__name__}"
        )(cls)

    return wrapper


class TestBackend(unittest.TestCase):
    ip = ipaddress.ip_address('1.2.3.4')
    backendClass = wireguard_totp.InMemoryOTPBackend

    @classmethod
    def setUpClass(cls):
        cls.backend = cls.backendClass()

    def test_connected_clients(self):
        clients = self.backend.get_connected_clients()
        self.assertEqual(clients, [])

        self.backend.save_connected_clients([])
        clients = self.backend.get_connected_clients()
        self.assertEqual(clients, [])

        self.backend.save_connected_clients([str(self.ip)])
        clients = self.backend.get_connected_clients()
        self.assertEqual(clients, [str(self.ip)])

    def test_seed(self):
        seed = self.backend.get_seed(self.ip)
        self.assertEqual(seed, None)

        self.backend.save_seed(self.ip, 'WIREGUARDTOTP')
        seed = self.backend.get_seed(self.ip)
        self.assertEqual(seed, 'WIREGUARDTOTP')

    def test_logged_until(self):
        logged_until = self.backend.get_logged_until(self.ip)
        self.assertEqual(logged_until, None)

        date = datetime(2019, 9, 18).isoformat()
        self.backend.save_logged_until(self.ip, date)
        self.assertEqual(self.backend.get_logged_until(self.ip), date)

        self.backend.save_logged_until(self.ip, 'logged-out')
        logged_until = self.backend.get_logged_until(self.ip)
        self.assertEqual(logged_until, 'logged-out')


@requireEnvVars('CONSUL_HTTP_ADDR')
class TestConsulBackend(TestBackend):
    backendClass = wireguard_totp.ConsulOTPBackend

    @classmethod
    def tearDownClass(cls):
        host = os.environ['CONSUL_HTTP_ADDR']
        requests.delete(host+'/v1/kv/wireguard-totp?recurse=true')


@requireEnvVars('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY')
class TestSSMOTPBackend(TestBackend):
    backendClass = wireguard_totp.SSMOTPBackend

    @classmethod
    def tearDownClass(cls):
        params = cls.backend._client.describe_parameters(
            ParameterFilters=[{
                'Key': 'Name',
                'Option': 'BeginsWith',
                'Values': ['/wireguard-totp']
            }]
        )
        cls.backend._client.delete_parameters(
            Names=[p['Name'] for p in params['Parameters']]
        )


class TestCLI(unittest.TestCase):
    fails = (
        (
            [],
            'usage: python3 -m unittest [-h] --backend BACKEND --destination DESTINATION\n'
            '                           --address ADDRESS --port PORT\n'
            'python3 -m unittest: error: the following arguments are required: --backend, --destination, --address, --port\n'
        ),
        (
            ['--backend', 'foo', '--destination', '10.1.2.0/16', '--address', '192.168.1.2', '--port', '40'],
            "usage: python3 -m unittest [-h] --backend BACKEND --destination DESTINATION\n"
            "                           --address ADDRESS --port PORT\n"
            "python3 -m unittest: error: argument --destination: invalid ip_network value: '10.1.2.0/16'\n"
        )
    )
    success = (
        (
            ['--backend', 'foo', '--destination', '10.1.2.0/24', '--address', '192.168.1.2', '--port', '40'],
            dict(backend='foo', address=IPv4Address('192.168.1.2'), destination=IPv4Network('10.1.2.0/24'), port=40)
        ),
    )

    def test_wrong_args(self):
        parser = wireguard_totp.get_parser()
        for args, expected in self.fails:
            with self.subTest(args=args):
                f = io.StringIO()
                with self.assertRaises(SystemExit), \
                     contextlib.redirect_stderr(f), \
                     patch.dict(os.environ, {'COLUMNS': '80'}), \
                     patch('sys.argv', ['w-totp']+args):
                    parser.parse_args()

                self.assertEqual(f.getvalue(), expected)

    def test_good_args(self):
        parser = wireguard_totp.get_parser()
        for args, expected in self.success:
            f = io.StringIO()

            with self.subTest(args=args), \
                 contextlib.redirect_stderr(f), \
                 patch('sys.argv', ['w-totp']+args):
                self.assertEqual(f.getvalue(), '')
                self.assertEqual(vars(parser.parse_args()), expected)

    def test_import_string(self):
        self.assertIs(
            wireguard_totp.import_string('InMemoryOTPBackend'),
            wireguard_totp.InMemoryOTPBackend
        )
        self.assertIs(
            wireguard_totp.import_string('ipaddress.IPv4Address'),
            IPv4Address
        )


class TestWireguardOTP(TestCase):
    @classmethod
    def setUpClass(cls):
        def mock(*args, **kwargs): pass
        wireguard_totp.WireguardOTPHandler._insert_rule = mock
        wireguard_totp.WireguardOTPHandler._delete_rule = mock

        def run_test_server():
            cls.backend = wireguard_totp.InMemoryOTPBackend()
            with wireguard_totp.WireguardOTPServer(('127.0.0.1', 4040),
                                     '1.2.3.0/24', cls.backend) as server:
                server.serve_forever()

        cls.server_thread = threading.Thread(target=run_test_server)
        # Exit the server thread when the main thread terminates
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.1)

    def send(self, msg):
        msg += '\n'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(('127.0.0.1', 4040))
            sock.sendall(msg.encode())
            return sock.recv(1024).decode().strip()

    def assertCommand(self, command, expected):
        """Shortcut to send a command and check the response is correct."""
        response = self.send(command)
        self.assertEqual(response, expected)

    def test_wireguard(self):
        error = "error command 'wrong_command' does not exists"
        self.assertCommand('wrong_command', error)
        self.assertCommand('wrong_command argument', error)

        # We have three states and four commands possible each time.

        # Unregistered
        self.assertCommand('status', 'ok unregistered')
        self.assertCommand('login 1234', 'fail')
        # Logout will always wotk no matter what happens.
        self.assertCommand('logout', 'ok')
        status, seed, uri = self.send('init').split(' ')
        self.assertEqual(status, 'ok')

        # Logged out
        self.assertCommand('status', 'ok logged-out')
        self.assertCommand('login 1234', 'fail')
        self.assertCommand('logout', 'ok')
        self.assertCommand('init', 'fail')

        totp = pyotp.TOTP(seed)
        response = self.send(f'login {totp.now()}')
        status, _, logged_until = response.partition(' ')
        self.assertEqual(status, 'ok')
        # Let's just check this is a correct ISO 8601 datetime.
        datetime.fromisoformat(logged_until)

        # Logged in
        response = self.send('status')
        ok, status, logged_until = response.split(' ')
        self.assertEqual(ok, 'ok')
        self.assertEqual(status, 'logged-in')
        datetime.fromisoformat(logged_until)
        self.assertCommand('init', 'fail')
        self.assertCommand(f'login {totp.now()}', 'fail')

        class MockDatetime(datetime):
            @classmethod
            def now(cls):
                return super().now() + timedelta(hours=3)

        with patch('wireguard_totp.datetime', MockDatetime):
            self.assertCommand('status', 'ok logged-out')

        self.assertCommand('logout', 'ok')
        self.assertCommand('status', 'ok logged-out')

        # Let's login again and test _sync_firewall() with multiple clients
        # connected
        logged_until = datetime.now() + timedelta(hours=2)
        self.backend.save_logged_until(
            IPv4Address('4.5.6.7'),
            logged_until.isoformat()
        )
        self.backend.save_connected_clients(['4.5.6.7'])
        status, _, _ = self.send(f'login {totp.now()}').partition(' ')
        self.assertTrue(status, 'ok')
        self.assertCommand('logout', 'ok')
        self.assertCommand('status', 'ok logged-out')


# TODO: return 'fail' when an exception is raised
# TODO: change save/get seed so they can have another implementation
# TODO: test what _insert/remove_rule are doing
# TODO: update and test the client
# TODO: implement renew
