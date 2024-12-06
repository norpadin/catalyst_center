import requests
from requests.auth import HTTPBasicAuth
import urllib3
import os
import time
from datetime import datetime, timedelta
import pprint
import json
import sys
from pathlib import Path
import logging
from tqdm import tqdm, trange
from typing import Optional
from io import StringIO
import argparse

'''
    _summary_
    _version_number_ = "1.0.4"
    _author_ = "npadin"
    _description_ = "Métodos para interactuar con Cisco Catalyst Control Center vía APIs"
    _copyright_ = "Copyright 2024, npadin"
    _license_ = "MIT License"  
    _status_ = "Development"
    _changelog_ = " v1 versión inicial"
    
    Returns:
        _type_: _description_
        
    Example usage:
        python dnac_oop.py --prime-ip (ipv4 or fqdn) --username user --password pass
        
        python dnac_oop.py --prime-ip 10.1.100.10 --username admin --password P4ssw0rd
    '''
    
    
class TQDMStreamHandler(logging.StreamHandler):
    def __init__(self, stream=sys.stdout):
        super().__init__(stream)
        self._original_stream = stream
        self._capture_stream = StringIO()

    def emit(self, record):
        if tqdm._instances:
            self._capture_stream.write(self.format(record) + "\n")
        else:
            super().emit(record)

    def get_log_content(self):
        return self._capture_stream.getvalue()


class Dnac:
    def __init__(
            self, dnac_ip: str, dnac_user: str, dnac_password: str) -> None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._session = requests.Session()
        self._session.headers.update({'content-type': 'application/json'})
        self.dnac_user: str = dnac_user
        self.dnac_password: str = dnac_password
        self.dnac_ip: str = dnac_ip
        self.base_url = f"https://{dnac_ip}"
        self.auth_url = "/dna/system/api/v1/auth/token"
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        
    def __repr__(self) -> str:
        return (f"Dnac(dnac_ip='{self.dnac_ip}', "
                f"dnac_user='{self.dnac_user}'")

    def __str__(self) -> str:
        return (f"Cisco DNA Center at '{self.dnac_ip}'\n"
                f"User: {self.dnac_user}\n")

    def _refresh_token(self) -> None:
        try:
            response = self._session.post(
                self.base_url + self.auth_url,
                auth=HTTPBasicAuth(self.dnac_user, self.dnac_password),
                verify=False
            )
            response.raise_for_status()
            self._token = response.json().get("Token")
            self._token_expiry = datetime.now() + timedelta(hours=1)  # Assume 1-hour validity
            self._session.headers.update({"X-Auth-Token": self._token})
            logger.info("Token refreshed successfully.")
        except Exception as e:
            logger.exception("Failed to refresh token.")

    def _ensure_token(self) -> None:
        if not self._token or (
                self._token_expiry and datetime.now() >= self._token_expiry):
            self._refresh_token()

    def _request(
            self, method: str, endpoint: str, **kwargs) -> requests.Response:
        self._ensure_token()
        url = self.base_url + endpoint
        response = self._session.request(method, url, verify=False, **kwargs)
        response.raise_for_status()
        return response


    def get_token(self) -> str | None:
        try:
            token = requests.post(
                self.base_url + self.auth_url,
                auth=HTTPBasicAuth(
                    username=self.dnac_user,
                    password=self.dnac_password
                ),
                headers={'content-type': 'application/json'},
                verify=False,
            )
            data = token.json()
            logger.info(
                f"DNAC Token received OK.")
            return data["Token"]
        except Exception as e:
            logger.error(f"Error getting token: {e}")
            return None

    def get_all_devices(self) -> dict | None:
        endpoint = "/dna/intent/api/v1/network-device"
        try:
            devices = {}
            while endpoint:
                response = self._request("GET", endpoint)
                data = response.json()
                for device in data.get('response', []):
                    devices[device['id']] = [
                        device['hostname'],
                        device['managementIpAddress'],
                        device['platformId']
                    ]
                endpoint = data.get('pagination', {}).get('next', None)
            self.devices = devices
            return self.devices
        except Exception as e:
            logger.exception("Error getting all devices.")
            return None

    
    
    def get_devices_by_platfom(self, type) -> list[str] | None:
        url: str = self.base_url + r'/dna/intent/api/v1/network-device'
        self.devices_by_platform: list = []
        self.type: str = type
        self.query_string_params: dict = {'platformId': self.type}
        try:
            response: requests.Response = requests.get(
                url,
                headers={
                    'X-Auth-Token': self.get_token(),
                    'Content-type': 'application/json',
                },
                params=self.query_string_params,
                verify=False
            )
            for device in response.json()['response']:
                self.devices_by_platform.append(device['id'])
            return self.devices_by_platform
        except Exception as e:
            self.logger.error(f"Error getting device info: {e}")
            return None

    def get_device_by_ip(self, device_ip) -> str | None:
        devices_url = r'/dna/intent/api/v1/network-device'
        try:
            response: requests.Response = requests.get(
                self.base_url + devices_url + f'/ip-address/{device_ip}',
                headers={
                    'X-Auth-Token': self.get_token(),
                    'Content-type': 'application/json',
                },
                verify=False
            )
            return response.json()
        except Exception as e:
            self.logger.error(f"Error getting device info: {e}")
            return None

    def send_commands(self) -> None:
        pass

    def get_facts(self, device) -> None:
        self.device = device
        payload: dict = {
            'commands': [
                'show ip int brief'
            ],
            'deviceUuids': self.device,
            'timeout': 0
        }
        command_runner_send_url: str = r'/dna/intent/api/v1/network-device-poller/cli/read-request'
        TASK_BY_ID_URL: str = '/dna/intent/api/v1/task/{task_id}'
        FILE_GET_BY_ID: str = '/dna/intent/api/v1/file/{file_id}'
        try:
            response = requests.post(
                self.base_url + command_runner_send_url, data=json.dumps(payload),
                headers={
                    'X-Auth-Token': self.get_token(),
                    'Content-type': 'application/json'
                },
                verify=False)
            task_id = response.json()['response']['taskId']
            return task_id
        except Exception as e:
            logger.error(f"Error sending CLI command: {e}")
            return None

    def get_task_result(self) -> None:
        pass

    def get_file_contents(self) -> None:
        pass

    def get_device_count(self) -> int:
        devices_count_url = '/dna/intent/api/v1/network-device/count'
        response = requests.get(self.base_url + devices_count_url,
                                headers={
                                    'X-Auth-Token': self.get_token(),
                                    'Content-type': 'application/json'
                                },
                                verify=False)
        return int(response.json()['response'])

    def get_device_list(self) -> None:
        pass

    def get_device_by_id(self):
        pass

    def get_device_by_serial(self):
        pass


def setup_logger(log_file: str = "dnac.log") -> logging.Logger:
    if log_file is None:
        log_file = f"dnac{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

    logger: logging.Logger = logging.getLogger('myLogger')
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file, mode='w')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    log_handler = TQDMStreamHandler(sys.stdout)
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

    return logger

def parse_args() -> argparse.Namespace:
    # Import default values from config
    from dnac_config import USER, PASSWORD, DNAC

    parser = argparse.ArgumentParser(
        description="Cisco Prime API Interactor Script"
    )
    parser.add_argument(
        "--dnac-ip",
        default=DNAC,  # Use default from pi_config.py if not provided
        help=f"IP address or hostname of the Cisco Prime server (default: {DNAC})"
    )
    parser.add_argument(
        "--username",
        default=USER,  # Use default from pi_config.py if not provided
        help=f"Username for API authentication (default: {USER})"
    )
    parser.add_argument(
        "--password",
        default=PASSWORD,  # Use default from pi_config.py if not provided
        help="Password for API authentication (default: value from pi_config.py)"
    )
    parser.add_argument(
        "--log-file",
        default="prime.log",
        help="Path to the log file (default: prime.log)"
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=1000,
        help="Maximum number of results per API call (default: 1000)"
    )
    return parser.parse_args()


def main() -> None:
    args: argparse.Namespace = parse_args()
    dnac = Dnac(args.dnac_ip, args.username, args.password)
    print(dnac)
    print(f'Cantidad de dispositivos: {dnac.get_device_count()}')
    pprint.pp(dnac.get_all_devices())
    pprint.pp(dnac.get_devices_by_platfom('AIR-AP2802I-A-K9'))
    pprint.pp(dnac.get_device_by_ip('10.1.100.3'))


if __name__ == "__main__":
        os.system('cls' if os.name == 'nt' else 'clear')
        logger: logging.Logger = setup_logger()
        main()
