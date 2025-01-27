# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVE_Project
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import requests, os, json
from dotenv           import load_dotenv
from request_payloads import *
from display          import Display



class System:

    def __init__(self):
        load_dotenv()
        self._ZABBIX_URL = os.getenv("ZABBIX_URL")
        self._USER       = os.getenv("USER")
        self._PASSWORD   = os.getenv("PASSWORD")
        self._HEADERS    = {"Content-Type": "application/json"}
        self._token      = None
        self._all_hosts  = None

    
    def _execute(self) -> None:
        try:
            self._get_authentication_token()
            self._get_all_hosts()
            self._display_results()
        except KeyboardInterrupt:  print(f'{Display.red("Process stopped")}')
        except Exception as error: print(f'{Display.red("Unknown error:")}\n{error}')


    def _get_authentication_token(self) -> None:
        payload  = token_request_payload(self._USER, self._PASSWORD)
        response = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(payload))
        self._token = response.json()["result"]


    def _get_all_hosts(self) -> None:
        payload  = all_hosts_request_payload(self._token)
        response = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(payload))
        self._all_hosts = response.json()["result"]

    
    def _display_results(self) -> None:
        for host in self._all_hosts:
            print(f"\nHost: {host['name']} (ID: {host['hostid']})")
            items = self._get_item_information_of_a_host(host["hostid"])
            if not items:
                print("  Nenhum item encontrado.")
            else:
                for item in items:
                    print(f"  - {item['name']}: {item.get('lastvalue', 'Sem valor registrado')}")


    def _get_item_information_of_a_host(self, hostid:str):
        payload = information_request_payload(hostid, self._token)
        try:
            response = requests.post(self._ZABBIX_URL, headers=self._HEADERS, data=json.dumps(payload))
            response.raise_for_status()
            result = response.json()
            if "result" in result:
                return result["result"]
            else:
                print("Erro: Resposta inesperada da API:", result)
                return []
        except requests.exceptions.RequestException as e:
            print(f"Erro ao se comunicar com o Zabbix: {e}")
            return []




if __name__ == "__main__":
    system = System()
    system._execute()