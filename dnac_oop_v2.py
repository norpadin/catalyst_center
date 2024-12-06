import requests
from requests.auth import HTTPBasicAuth
import urllib3
import logging
from datetime import datetime, timedelta
from typing import Optional, Union
from tqdm import tqdm
import pprint
import os
from io import StringIO
import argparse
import json
import sys
from pathlib import Path

'''
    _summary_
    _version_number_ = "2.0.1"
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
            self, dnac_ip: str, dnac_user: str, dnac_password: str,
            logger: logging.Logger) -> None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.dnac_ip: str = dnac_ip
        self.dnac_user: str = dnac_user
        self.dnac_password: str = dnac_password
        self.base_url: str = f"https://{dnac_ip}"
        self.auth_url = r"/dna/system/api/v1/auth/token"
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self.devices: dict = {}
        self.logger: logging.Logger = logger
        self.logger.info("Dnac class initialized successfully.")

    def __repr__(self) -> str:
        return f"Dnac(dnac_ip='{self.dnac_ip}', dnac_user='{self.dnac_user}')"

    def __str__(self) -> str:
        return f"Cisco DNA Center at '{
            self.dnac_ip} '\nUser: {
            self.dnac_user} \n"

    def _refresh_token(self) -> None:
        """
        Retrieve a new authentication token and update its expiry.
        """
        try:
            response = requests.post(
                self.base_url + self.auth_url,
                auth=HTTPBasicAuth(self.dnac_user, self.dnac_password),
                headers={"Content-Type": "application/json"},
                verify=False,
            )
            response.raise_for_status()
            self._token = response.json()["Token"]
            self._token_expiry = datetime.now() + timedelta(hours=1)  # Assume 1-hour validity
            self.logger.info("Token refreshed successfully.")
        except requests.RequestException as e:
            self.logger.error(f"Error refreshing token: {e}")
            raise

    def _get_token(self) -> str:
        """
        Return a valid token, refreshing it if needed.
        """
        if not self._token or datetime.now() >= self._token_expiry:
            self._refresh_token()
            self.logger.info(f"DNAC Token received OK!")
        return self._token

    def _request(self, method: str, endpoint: str, params: dict = None,
                 data: dict = None) -> Union[dict, None]:
        """
        A generic method for making API requests.
        """
        url: str = self.base_url + endpoint
        headers: dict[str, str] = {
            "X-Auth-Token": self._get_token(),
            "Content-Type": "application/json",
        }
        try:
            response: requests.Response = requests.request(
                method, url, headers=headers, params=params, json=data,
                verify=False)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.error(f"Error during API call to {url}: {e}")
            return None

    def get_all_devices(self) -> dict:
        endpoint = "/dna/intent/api/v1/network-device"
        response = self._request("GET", endpoint)
        if response:
            self.logger.info("All devices fetched successfully.")
            for device in tqdm(
                    response.get("response", []),
                    desc="Fetching devices"):
                self.devices[device["id"]] = [
                    device["hostname"],
                    device["managementIpAddress"],
                    device["platformId"],
                ]
        else:
            self.logger.info("No devices found.")
        return self.devices

    def get_devices_by_platform(self, platform: str) -> list[str]:
        endpoint = "/dna/intent/api/v1/network-device"
        params: dict = {"platformId": platform}
        devices_by_platform = []
        response = self._request("GET", endpoint, params=params)
        if response:
            self.logger.info(f"All {platform} devices fetched successfully.")
            devices_by_platform: list = [device["id"]
                                   for device in response.get(
                                       "response", [])]
        else:
            self.logger.info(f"No devices found by {platform}.")
        return devices_by_platform

    def get_device_by_ip(self, device_ip: str) -> Optional[dict]:
        endpoint: str = f"/dna/intent/api/v1/network-device/ip-address/{device_ip}"
        return self._request("GET", endpoint)

    def get_device_count(self) -> int:
        endpoint = "/dna/intent/api/v1/network-device/count"
        response = self._request("GET", endpoint)
        return int(response.get("response", 0)) if response else 0

    def send_commands(
            self, device_uuid: str, commands: list[str]) -> Optional[str]:
        endpoint = "/dna/intent/api/v1/network-device-poller/cli/read-request"
        payload = {
            "commands": commands,
            "deviceUuids": [device_uuid],
            "timeout": 0,
        }
        response = self._request("POST", endpoint, data=payload)
        if response:
            return response.get("response", {}).get("taskId")
        return None

    def get_facts(self, device_uuid: str) -> Optional[str]:
        return self.send_commands(device_uuid, ["show ip int brief"])


def setup_logger(log_file: str = "dnac.log") -> logging.Logger:
    # Create or get the logger instance
    logger: logging.Logger = logging.getLogger('DNAC_logger')

    # Prevent duplicate log entries by clearing existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.setLevel(logging.INFO)

    # File handler for writing logs to a file
    file_handler = logging.FileHandler(
        log_file, mode='w')  # Overwrite each run
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    # Console handler for printing logs with `tqdm` compatibility
    log_handler = TQDMStreamHandler(sys.stdout)
    log_handler.setLevel(logging.INFO)
    log_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'))
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
        default="dnac.log",
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
    logger: logging.Logger = setup_logger(args.log_file)
    dnac = Dnac(args.dnac_ip, args.username, args.password, logger)
    print(dnac)
    print(f'Cantidad de dispositivos: {dnac.get_device_count()}')
    pprint.pp(dnac.get_all_devices())
    pprint.pp(dnac.get_devices_by_platform('AIR-AP2802I-A-K9'))
    pprint.pp(dnac.get_device_by_ip('10.1.100.3'))


if __name__ == "__main__":
        os.system('cls' if os.name == 'nt' else 'clear')
        main()
