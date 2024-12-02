import requests
from requests.auth import HTTPBasicAuth
from dnac_config import USER, PASSWORD, DNAC
import urllib3
import logging
import os
from datetime import datetime
import pprint


logger: logging.Logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('dnac.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_token():
    token = requests.post(
        f'https://{DNAC}/dna/system/api/v1/auth/token',
        auth=HTTPBasicAuth(
            username=USER,
            password=PASSWORD
        ),
        headers={'content-type': 'application/json'},
        verify=False,
    )
    data = token.json()
    return data["Token"]


def get_device_from_dnac(device_ip):
    response = requests.get(
        f'https://{DNAC}/dna/intent/api/v1/network-device/ip-address/{device_ip}',
        headers={
            'X-Auth-Token': '{}'.format(get_token()),
            'Content-type': 'application/json',
        },
        verify=False
    )
    return response.json()


def main() -> None:
    pprint.pp(get_device_from_dnac('10.1.100.3'))


if __name__ == "__main__":
    main()
