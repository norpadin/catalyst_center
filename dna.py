import requests

'''
class CatalystCenter(self):
    def __init__(self):
        self.token = self.get_token()
        self.url = "https://10.1.100.10/dna/system/api/v1/network-device"
        self.headers = {
            "X-Auth-Token": self.token,
            "Content-Type": "application/json"
        }

        '''


def get_token(self):
    token = requests.post(
        "https://10.1.100.10/dna/system/api/v1/auth/token",
        auth=HTTPBasicAuth(
            username="admin",
            password="BvsTv3965!"
        ),
        headers={'content-type': 'application/json'},
        verify=False,
    )
    data = token.json()
    return data["Token"]
