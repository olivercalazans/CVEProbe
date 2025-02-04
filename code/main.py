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
        self._all_hosts = None


    def _execute(self) -> None:
        try:
            self._get_all_hosts_from_zabbix()
            self._prepare_data_obtained_from_zabbix()
            print(self._all_hosts)
        except KeyboardInterrupt:  print(f'{Display.red("Process stopped")}')
        except Exception as error: print(f'{Display.red("Unknown error:")}\n{error}')


    def _get_all_hosts_from_zabbix(self) -> None:
        payload         = token_request_payload(os.getenv("USER"), os.getenv("PASSWORD"))
        token           = self._get_data_from_zabbix(payload)
        payload         = device_names_and_ip_payload(token)
        self._all_hosts = self._get_data_from_zabbix(payload)


    @staticmethod
    def _get_data_from_zabbix(payload:dict) -> str | dict:
        response = requests.post(os.getenv("ZABBIX_URL"), headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        return response.json()['result']


    def _prepare_data_obtained_from_zabbix(self) -> None:
        self._all_hosts = [{'name': dev['host'],'ip': dev['interfaces'][0]['ip']} for dev in self._all_hosts]





if __name__ == "__main__":
    system = System()
    system._execute()
