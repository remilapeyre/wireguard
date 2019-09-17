from __future__ import annotations
from typing import Union, Tuple, Optional, List, Dict

import os
import enum
import argparse
import logging
import pyotp
import sqlite3
import json
from importlib import import_module
from datetime import datetime, timedelta
import ipaddress

from socketserver import StreamRequestHandler, ThreadingTCPServer


logger = logging.getLogger('wireguard-otp')


IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class Status(enum.Enum):
    LOGGED_IN = 'logged-in'
    LOGGED_OUT = 'logged-out'
    UNREGISTERED = 'unregistered'


class BaseOTPBackend:
    # How many attempts can be done in a 30s window.
    # Settings this to 0 disable the cooldown period.
    # TODO(remi): Implement this
    max_tries = 5

    def __init__(self) -> None:
        self._attempts = None

    def _get(self, key: str) -> Optional[str]:
        raise NotImplementedError

    def _put(self, key: str, value: str) -> None:
        raise NotImplementedError

    def get_connected_clients(self) -> List[str]:
        clients = self._get('connected-clients')
        if clients is None:
            return []
        return json.loads(clients)  # type: ignore

    def save_connected_clients(self, clients: List[str]) -> None:
        self._put('connected-clients', json.dumps(clients))

    def get_seed(self, ip: IPAddress) -> Optional[str]:
        return self._get(f'seed/{ip}')

    def save_seed(self, ip: IPAddress, seed: str) -> None:
        self._put(f'seed/{ip}', seed)

    def get_logged_until(self, ip: IPAddress) -> Optional[str]:
        return self._get(f'logged_until/{ip}')

    def save_logged_until(self, ip: IPAddress, logged_until: str) -> None:
        self._put(f'logged_until/{ip}', logged_until)


class InMemoryOTPBackend(BaseOTPBackend):
    def __init__(self) -> None:
        super().__init__()
        self._data: Dict[str, str] = {}

    def _get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def _put(self, key: str, value: str) -> None:
        self._data[key] = value


try:
    import requests
    import base64
except ImportError:  # pragma: nocover
    # ConsulOTPBackend is not available without requests
    pass
else:
    class ConsulOTPBackend(BaseOTPBackend):
        def __init__(self) -> None:
            self._session = requests.Session()
            self._host = os.environ.get('CONSUL_HTTP_ADDR', 'http://127.0.0.1:8500')

        def _get(self, key: str) -> Optional[str]:
            url = f'{self._host}/v1/kv/wireguard-totp/{key}?raw=true'
            response = self._session.get(url)
            if response.status_code == 404:
                return None
            return response.text

        def _put(self, key: str, value: str) -> None:
            url = f'{self._host}/v1/kv/wireguard-totp/{key}'
            response = self._session.put(url, data=value.encode())
            response.raise_for_status()


try:
    import boto3
except ImportError:  # pragma: nocover
    # SSMOTPBackend is only available when boto3 is installed
    pass
else:
    class SSMOTPBackend(BaseOTPBackend):
        def __init__(self) -> None:
            self._client = boto3.client('ssm')

        def _get(self, key: str) -> Optional[str]:
            try:
                response = self._client.get_parameter(
                    Name=f'/wireguard-totp/{key}'
                )
                return str(response['Parameter']['Value'])
            except self._client.exceptions.ParameterNotFound:
                return None

        def _put(self, key: str, value: str) -> None:
            self._client.put_parameter(
                Name=f'/wireguard-totp/{key}',
                Type='String',
                Overwrite=True,
                Value=value
            )


class BaseWireGuardHandler(StreamRequestHandler):
    def handle(self) -> None:
        """Call the appropriate command handler and return the result.

        Return 'error ...' when the requested command does not exists.
        """
        ip, port = self.client_address
        logger.info('Client %s connected', ip)
        while True:
            try:
                command_name, _, arg = (
                    self.rfile.readline().decode().strip().partition(' ')
                )
            except (OSError, UnicodeError):  # pragma: nocover
                # the client probably left
                break

            if not command_name:
                break

            try:
                command = getattr(self, "do_{}".format(command_name))
            except AttributeError:
                response = "error command {!r} does not exists".format(command_name)
            else:
                logger.debug("%s: command: %s", ip, command_name)
                response = command(ip, arg)

            logger.debug('%s: response: %s', ip, response)
            response += '\n'
            try:
                self.wfile.write(response.encode())
                self.wfile.flush()
            except (OSError, UnicodeError):  # pragma: nocover
                # the client probably left
                break


class WireguardOTPHandler(BaseWireGuardHandler):
    server: WireguardOTPServer

    def _insert_rule(self, source: str, dest: str) -> None:  # pragma: nocover
        # We must guard this import when developping on Mac
        import iptc
        logger.info('Adding %s -> %s', source, dest)
        rule = {
            'src': source,
            'dst': dest,
            'target': 'ACCEPT'
        }
        iptc.easy.insert_rule('filter', 'INPUT', rule)

    def _delete_rule(self, source: str, dest: str) -> None:  # pragma: nocover
        import iptc
        logger.info('Removing %s -> %s', source, dest)
        rule = {
            'src': source,
            'dst': dest,
            'target': 'ACCEPT'
        }
        try:
            iptc.easy.delete_rule('filter', 'INPUT', rule)
        except iptc.IPTCError:
            pass

    def _sync_firewall(self, add: str = None, remove: str = None) -> None:
        logger.info('Syncing firewall rules')

        connected_clients = []
        disconnected_client = []
        for client in self.server.backend.get_connected_clients():
            ip = ipaddress.ip_address(client)
            if self._get_status(ip) == Status.LOGGED_IN and client != remove:
                connected_clients.append(client)
            else:
                disconnected_client.append(client)

        if add:
            connected_clients.append(add)
        if remove:
            disconnected_client.append(remove)

        # The order here (disconnect, save state, connect clients) is important
        # so we don't end up in a bad state if save_connected_clients() fails.

        for client in disconnected_client:
            self._delete_rule(client, self.server.destination)

        self.server.backend.save_connected_clients(connected_clients)

        for client in connected_clients:
            self._insert_rule(client, self.server.destination)

    def _get_status(self, ip: IPAddress) -> Status:
        logged_until = self.server.backend.get_logged_until(ip)

        if logged_until is None or logged_until == Status.LOGGED_OUT.value:
                seed = self.server.backend.get_seed(ip)
                if seed is None:
                    return Status.UNREGISTERED
                else:
                    return Status.LOGGED_OUT

        if datetime.fromisoformat(logged_until) < datetime.now():
            return Status.LOGGED_OUT
        else:
            return Status.LOGGED_IN

    def do_status(self, ip: IPAddress, _: str) -> str:
        """Return one of 'init', 'logged-in' or 'logged-out'."""
        status = self._get_status(ip)
        if status == Status.LOGGED_IN:
            logged_until = self.server.backend.get_logged_until(ip)
            return f'ok {status.value} {logged_until}'
        else:
            return f'ok {status.value}'

    def do_init(self, ip: IPAddress, _: str) -> str:
        """Return the totp secret the client needs to save.

        If the client already logged in successfully, he should not be able to
        call 'init' again. In this case, we return 'fail'.
        """
        if self._get_status(ip) != Status.UNREGISTERED:
            return 'fail'

        seed = pyotp.random_base32()
        self.server.backend.save_seed(ip, seed)

        totp = pyotp.TOTP(seed)
        url = totp.provisioning_uri(str(ip), issuer_name="WireGuard-OTP")
        return ' '.join(('ok', seed, url))

    def do_login(self, ip: IPAddress, otp: str) -> str:
        """Authenticate the user and open the firewall.

        Return 'ok' on success and 'fail' on failure.
        """
        if self._get_status(ip) != Status.LOGGED_OUT:
            return 'fail'

        seed = self.server.backend.get_seed(ip)
        assert seed is not None
        totp = pyotp.TOTP(seed)
        if not totp.verify(otp):
            return 'fail'

        logged_until = datetime.now() + timedelta(hours=2)
        self.server.backend.save_logged_until(ip, logged_until.isoformat())
        self._sync_firewall(add=str(ip))
        return f'ok {logged_until}'

    def do_logout(self, ip: IPAddress, _: str) -> str:
        """Deconnect the client and close the firewall.

        Always return 'ok'.
        """
        self.server.backend.save_logged_until(ip, Status.LOGGED_OUT.value)
        self._sync_firewall(remove=str(ip))
        return 'ok'


class WireguardOTPServer(ThreadingTCPServer):
    def __init__(self, server_address: Tuple[str, int], destination: str,
                 backend: BaseOTPBackend):
        super().__init__(server_address, WireguardOTPHandler)
        self.backend = backend
        self.destination = destination


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', type=str, required=True)
    parser.add_argument('--destination', type=ipaddress.ip_network, required=True)
    parser.add_argument('--address', type=ipaddress.ip_address, required=True)
    parser.add_argument('--port', type=int, required=True)

    return parser


def import_string(path: str) -> Any:
    try:
        module_path, class_name = path.rsplit('.', 1)
    except ValueError as err:
        return globals()[path]

    module = import_module(module_path)
    return getattr(module, class_name)


if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))
    parser = get_parser()
    args = parser.parse_args()

    backend = import_string(args.backend)()

    with WireguardOTPServer((str(args.address), args.port), args.destination, backend) as server:
        logger.info('Starting OTP server')
        server.serve_forever()
