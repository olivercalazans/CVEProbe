# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVEProbe
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from pysnmp.hlapi.v3arch import *
import os, json, sys, asyncio
import requests
from dotenv           import load_dotenv
from request_payloads import *
from oid              import *
from display          import *


class Main:

    def __init__(self):
        load_dotenv()
        self._hosts    = dict()
        self._oid_list = dict()


    def _read_oid_list(self) -> None:
        FILE_PATH = os.path.dirname(os.path.abspath(__file__))
        FILE_PATH = os.path.join(FILE_PATH, 'oid_manufacturer.json')
        try:
            with open(FILE_PATH, 'r', encoding='utf-8') as file:
                self._oid_list = json.load(file)
        except FileNotFoundError:  self._sys_exit('File "oid_manufacturer.json not found"')
        except Exception as error: self._sys_exit(f'Unknown error {error}')


    @staticmethod
    def _sys_exit(message:str) -> None:
        print(f'{red(message)}')
        sys.exit()


    def _execute(self) -> None:
        try:
            print('Reading oid_manufacturer.json file')
            self._read_oid_list()
            print('Getting data from zabbix')
            self._get_all_hosts_from_zabbix()
            print('Preparing data received from zabbix')
            self._prepare_data_obtained_from_zabbix()
            print('Getting additional data with SNMP')
            self._get_aditional_information_with_snmp()
            print(**self._hosts)
        except KeyboardInterrupt:  print(f'\n{red("Process stopped")}')
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
        updated_dict = dict()
        for dev in self._hosts:
            ip   = dev['interfaces'][0]['ip']
            name = dev['host']
            if os.getenv("NETS") in ip: continue
            updated_dict[ip] = {'name': name}
        self._hosts = updated_dict


    @staticmethod
    def _execute_snmpget(ip:str, oid:str) -> str:
        return Main._snmpget_async(ip, oid)


    @staticmethod
    async def _snmpget_async(ip, oid:str) -> str:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            SnmpEngine(),
            CommunityData(os.getenv("COMMUNITY"), mpModel=1),
            await UdpTransportTarget.create((ip, 161), timeout=1, retries=2),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        return str(varBinds[-1]) if varBinds else None


    def _get_aditional_information_with_snmp(self) -> None:
        len_devices = len(self._hosts)
        for index, dev in enumerate(self._hosts):
            sys.stdout.write(f'\rDevice: {index}/{len_devices}')
            sys.stdout.flush()
            self._get_manufacturer_name_and_oid(dev)
        print('\n')


    def _get_manufacturer_name_and_oid(self, ip:str) -> None:
        response          = asyncio.run(self._execute_snmpget(ip, '.1.3.6.1.2.1.1.2.0'))
        manufacturer_oid  = self._format_manufacturer_oid(response) if response else None
        manufacturer_name = self._oid_list.get(manufacturer_oid, None)
        self._hosts[ip]   = {'manufacturer': manufacturer_name, 'oid': manufacturer_oid}
        print(ip, self._hosts[ip])

    
    @staticmethod
    def _format_manufacturer_oid(oid:str) -> str:
        oid = oid.split('=')[-1]
        oid = oid.split('.')[:7]
        oid = '.'.join(oid)
        return oid




if __name__ == "__main__":
    system = Main()
    system._execute()
