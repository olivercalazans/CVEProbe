# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVE_Project
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import requests, os
import json
from dotenv  import load_dotenv
from getpass import getpass


class System:

    def __init__(self):
        load_dotenv()
        self._ZABBIX_URL = os.getenv("ZABBIX_URL")
        self._USER       = os.getenv("USER")
        self._PASSWORD   = getpass('Senha: ')
        self._HEADERS    = {"Content-Type": "application/json"}
        self._token      = None
        self._all_hosts  = None

    
    def _execute(self) -> None:
        try:
            self._get_authentication_token()
            self._get_all_hosts()
            self._display_results()
        except Exception as error: print()


    def _get_authentication_token(self) -> None:
        data = {
            "jsonrpc": "2.0",
            "method": "user.login",
            "params": {
                "user": self._USER,
                "password": self._PASSWORD,
            },
            "id": 1,
        }
        response = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(data))
        self._token = response.json()["result"]


    def _get_all_hosts(self) -> None:
        data = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["hostid", "name"],
            },
            "auth": self._token,
            "id": 2,
        }
        response = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(data))
        self._all_hosts = response.json()["result"]

    
    def _display_results(self) -> None:
        for host in self._all_hosts:
            print(f"\nHost: {host['name']} (ID: {host['hostid']})")
            items = self._get_item_information_of_a_host(host["hostid"])
            for item in items:
                print(f"  - {item['name']}: {item['lastvalue']}")

    
    def _get_item_information_of_a_host(self, hostid:str) -> None:
        data = {
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "output": ["itemid", "name", "lastvalue"],
                "hostids": hostid,
                "search": {
                    "name": ["CPU", "Memory", "Disk", "Software"],
                },
            },
            "auth": self._token,
            "id": 3,
        }
        response = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(data))
        return response.json()["result"]




if __name__ == "__main__":
    system = System()
    token  = system._execute()