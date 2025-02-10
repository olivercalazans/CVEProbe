# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVEProbe
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from pysnmp.hlapi.v3arch import *
import os, json, sys, asyncio, threading
import requests
from dotenv           import load_dotenv
from request_payloads import *
from oid              import *
from display          import *


class Main:

    def __init__(self):
        load_dotenv()
        self._oid_list           = dict()
        self._LOCK               = threading.Lock()
        self._hosts              = dict()
        self._unreacheable_hosts = list()


    def _execute(self) -> None:
        try:
            self._read_oid_list()
            self._get_all_hosts_from_zabbix()
            self._prepare_data_obtained_from_zabbix()
            self._get_manufacturer_oid_and_name()
            self._remove_hosts_without_response()
            print(self._hosts)
        except KeyboardInterrupt:  print(f'\n{red("Process stopped")}')
        except Exception as error: print(f'{red("Unknown error:")}\n{error}')


    def _read_oid_list(self) -> None:
        print('Reading oid_manufacturer.json file')
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


    def _get_all_hosts_from_zabbix(self) -> None:
        print('Getting data from zabbix')
        payload     = token_request_payload(os.getenv("USER"), os.getenv("PASSWORD"))
        token       = self._get_data_from_zabbix(payload)
        payload     = device_names_and_ip_payload(token)
        self._hosts = self._get_data_from_zabbix(payload)


    @staticmethod
    def _get_data_from_zabbix(payload:dict) -> str | dict:
        response = requests.post(os.getenv("ZABBIX_URL"), headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        return response.json()['result']


    def _prepare_data_obtained_from_zabbix(self) -> None:
        print('Preparing data received from zabbix')
        NETWORKS     = os.getenv("NETS").split('-')
        updated_dict = dict()
        for dev in self._hosts:
            ip = dev['interfaces'][0]['ip']
            if not ip[:11] in NETWORKS: continue
            updated_dict[ip] = {'name': dev['host']}
        self._hosts = updated_dict


    @staticmethod
    def _execute_snmpget(ip:str, oid:str) -> str:
        return asyncio.run(Main._snmpget_async(ip, oid))


    @staticmethod
    async def _snmpget_async(ip:str, oid:str) -> str:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            SnmpEngine(),
            CommunityData(os.getenv("COMMUNITY"), mpModel=1),
            await UdpTransportTarget.create((ip, 161), timeout=1, retries=2),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        return str(varBinds[-1]) if varBinds else None


    def _get_manufacturer_oid_and_name(self) -> None:
        print('Getting manufacturer OID')
        thread_list = list()
        for ip in self._hosts:
            thread = threading.Thread(target=self._get_oid_and_name, args=(ip,))
            thread_list.append(thread)
            thread.start()
        for thread in thread_list:
            thread.join()


    def _get_oid_and_name(self, ip:str) -> str:
        response = self._execute_snmpget(ip, '.1.3.6.1.2.1.1.2.0')
        if response:
            self._get_manufacturer_name(ip, response)
        else:
            with self._LOCK:
                self._unreacheable_hosts.append(ip)


    def _get_manufacturer_name(self, ip:str, response:str) -> None:
        manufacturer_oid  = self._format_manufacturer_oid(response)
        manufacturer_name = self._oid_list.get(manufacturer_oid, None)
        with self._LOCK:
            self._hosts[ip] = {'manufacturer': manufacturer_name, 'oid': manufacturer_oid}


    @staticmethod
    def _format_manufacturer_oid(oid:str) -> str:
        oid = oid.split('=')[-1]
        oid = oid.split('.')[:7]
        oid = '.'.join(oid)
        return oid.strip()


    def _remove_hosts_without_response(self) -> None:
        print('Removing hosts without response')
        self._hosts = {ip: self._hosts[ip] for ip in self._hosts if not ip in self._unreacheable_hosts}





if __name__ == "__main__":
    system = Main()
    system._execute()