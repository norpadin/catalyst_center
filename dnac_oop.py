import requests
from requests.auth import HTTPBasicAuth
from dnac_config import USERNAME, PASSWORD, BASE_URL
import urllib3
import logging
import os
import time
from datetime import datetime
import pprint
import json


logger: logging.Logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('dnac.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Dnac():
    def __init__(self,  dnac_url, dnac_user, dnac_password) -> None:
        self.dnac_user = dnac_user
        self.dnac_password = dnac_password
        self.base_url = dnac_url
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


def main() -> None:
    dnac = Dnac(BASE_URL, USERNAME, PASSWORD)
    print(f'Cantidad de dispositivos: {dnac.get_device_count()}')
    pprint.pp(dnac.get_all_devices())
    pprint.pp(dnac.get_devices_by_platfom('AIR-AP2802I-A-K9'))
    pprint.pp(dnac.get_device_by_ip('10.1.100.3'))


if __name__ == "__main__":
    main()
