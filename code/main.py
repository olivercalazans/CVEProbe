# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVEProbe
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import requests, os, json
from dotenv           import load_dotenv
from request_payloads import *
from oid              import *
from display          import Display



class System:

    def __init__(self):
        load_dotenv()
        self._ZABBIX_URL = os.getenv("ZABBIX_URL")
        self._HEADERS    = {"Content-Type": "application/json"}
        self._token      = None
        self._all_hosts  = None


    def _execute(self) -> None:
        try:
            self._get_zabbix_authentication_token()
            self._get_all_hosts_from_zabbix()
            self._prepare_data_obtained_from_zabbix()
        except KeyboardInterrupt:  print(f'{Display.red("Process stopped")}')
        except Exception as error: print(f'{Display.red("Unknown error:")}\n{error}')


    def _get_zabbix_authentication_token(self) -> None:
        payload     = token_request_payload(os.getenv("USER"), os.getenv("PASSWORD"))
        response    = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(payload))
        self._token = response.json()["result"]


    def _get_all_hosts_from_zabbix(self) -> None:
        payload         = device_names_and_ip_payload(self._token)
        response        = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(payload))
        self._all_hosts = response.json()["result"]

    
    def _prepare_data_obtained_from_zabbix(self) -> None:
        self._all_hosts = [{'name': dev['host'],'ip': dev['interfaces'][0]['ip']} for dev in self._all_hosts]





if __name__ == "__main__":
    system = System()
    system._execute()
