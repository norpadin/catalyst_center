import requests
from requests.auth import HTTPBasicAuth
import urllib3
import logging
import os
import time
from datetime import datetime
import pprint
import json
import os
import sys
from pathlib import Path
import logging
from tqdm import tqdm, trange
from typing import Optional
from io import StringIO
import argparse


logger: logging.Logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('dnac.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

class Dnac():
    def __init__(self,  dnac_ip, dnac_user, dnac_password) -> None:
        self.dnac_user = dnac_user
        self.dnac_password = dnac_password
        self.base_url = f"https://{dnac_ip}"
        self.auth_url = r'/dna/system/api/v1/auth/token'
        self.devices = {}
        self.sites = []
        self.groups = []
        self.dev_groups = []

    def __repr__(self) -> None:
        pass

    def __str__(self) -> None:
        pass

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
        devices_url = r'/dna/intent/api/v1/network-device'
        try:
            response = requests.get(
                self.base_url + devices_url,
                headers={
                    'X-Auth-Token': self.get_token(),
                    'Content-type': 'application/json',
                },
                verify=False
            )
            for device in response.json()['response']:
                self.devices.update({device['id']: [
                    device['hostname'], device['managementIpAddress'], device['platformId']]})
            return self.devices
        except Exception as e:
            logger.error(f"Error getting device info: {e}")
            return None

    def get_devices_by_platfom(self, type) -> list[str] | None:
        self.devices_by_platform = []
        self.type = type
        self.query_string_params = {'platformId': self.type}
        try:
            response = requests.get(
                self.base_url + self.devices_url,
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
            logger.error(f"Error getting device info: {e}")
            return None

    def get_device_by_ip(self, device_ip) -> str | None:
        devices_url = r'/dna/intent/api/v1/network-device'
        try:
            response = requests.get(
                self.base_url + devices_url + f'/ip-address/{device_ip}',
                headers={
                    'X-Auth-Token': self.get_token(),
                    'Content-type': 'application/json',
                },
                verify=False
            )
            return response.json()
        except Exception as e:
            logger.error(f"Error getting device info: {e}")
            return None

    def send_commands(sekf) -> None:
        pass

    def get_facts(self, device) -> None:
        self.device = device
        payload = {
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


def setup_logger(log_file: str = "prime.log") -> logging.Logger:
    if log_file is None:
        log_file = f"prime_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

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

def parse_args():
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
    print(f'Cantidad de dispositivos: {dnac.get_device_count()}')
    pprint.pp(dnac.get_all_devices())
    pprint.pp(dnac.get_devices_by_platfom('AIR-AP2802I-A-K9'))
    pprint.pp(dnac.get_device_by_ip('10.1.100.3'))


if __name__ == "__main__":
        os.system('cls' if os.name == 'nt' else 'clear')
        logger: logging.Logger = setup_logger()
        main()
