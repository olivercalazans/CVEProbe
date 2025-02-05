# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVEProbe
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import os, json, sys, asyncio
import requests
from pysnmp.hlapi.v3arch import *
from dotenv              import load_dotenv
from request_payloads    import *
from oid                 import *
from display             import *


class System:

    def __init__(self):
        load_dotenv()
        self._hosts    = dict()
        self._oid_list = dict()


    def _read_oid_list(self) -> dict:
        try:
            with open('oid_manufacturer.json', 'r', encoding='utf-8') as file:
                self._oid_list = json.load(file)
        except FileNotFoundError:  self._sys_exit('File "oid_manufacturer.json not found"')
        except Exception as error: self._sys_exit(f'Unknown error {error}')


    @staticmethod
    def _sys_exit(message:str) -> None:
        print(f'{red(message)}')
        sys.exit()


    def _execute(self) -> None:
        try:
            self._read_oid_list()
            self._get_all_hosts_from_zabbix()
            self._prepare_data_obtained_from_zabbix()
        except KeyboardInterrupt:  print(f'{red("Process stopped")}')
        except Exception as error: print(f'{red("Unknown error:")}\n{error}')


    def _get_all_hosts_from_zabbix(self) -> None:
        payload     = token_request_payload(os.getenv("USER"), os.getenv("PASSWORD"))
        token       = self._get_data_from_zabbix(payload)
        payload     = device_names_and_ip_payload(token)
        self._hosts = self._get_data_from_zabbix(payload)


    @staticmethod
    def _get_data_from_zabbix(payload:dict) -> str | dict:
        response = requests.post(os.getenv("ZABBIX_URL"), headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        return response.json()['result']


    def _prepare_data_obtained_from_zabbix(self) -> None:
        updated_dict = {dev['interfaces'][0]['ip']: {'name': dev['host']} for dev in self._hosts}
        self._hosts  = updated_dict


    @staticmethod
    async def _snmpget(ip, oid:str) -> str:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            SnmpEngine(),
            CommunityData(os.getenv("COMMUNITY"), mpModel=1),
            await UdpTransportTarget.create((ip, 161), timeout=1, retries=2),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        return varBinds


    def _get_aditional_information_with_snmp(self) -> None:
        for dev in self._hosts:
            self._get_manufacturer_name_and_oid(dev)


    def _get_manufacturer_name_and_oid(self, ip:str) -> None:
        response          = asyncio.run(self._snmpget(ip, '.1.3.6.1.2.1.1.2.0'))
        manufacturer_oid  = response.split('.', 7)[0]
        manufacturer_name = self._oid_list.get(manufacturer_oid, None)
        self._hosts[ip]   = {'manufacturer': manufacturer_name, 'oid': manufacturer_oid}


    @staticmethod
    def _format_snmp_response(response:str) -> str:
        return response.split('=')[-1].strip('"')





if __name__ == "__main__":
    system = System()
    system._execute()
