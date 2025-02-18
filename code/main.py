# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVEProbe
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from pysnmp.hlapi.v3arch import *
import os, json, sys, asyncio, threading, ipaddress
import requests
from functools        import lru_cache
from dotenv           import load_dotenv
from request_payloads import *
from oid              import *
from display          import *


class Main:

    OID_LIST = dict()
    MAPPING  = {
        'HPE':          hpe,
        'HP':           hpe,
        '1920-8G-PoE+': hp_1920,
        'Aruba':        aruba_jl357a,
        'Ruckus':       ruckus_oid
    }

    def __init__(self):
        load_dotenv()
        self._LOCK               = threading.Lock()
        self._thread_local_var   = threading.local()
        self._hosts              = dict()
        self._unreacheable_hosts = list()


    def _execute(self) -> None:
        try:
            self._read_oid_list()
            self._get_all_hosts_from_zabbix()
            self._prepare_data_obtained_from_zabbix()
            self._get_additional_information_if_possible()
            self._remove_hosts_without_response()
            self._sort_ip_addresses()
            self._display_result(self._hosts)
        except KeyboardInterrupt:  print(f'\n{red("Process stopped")}')
        except Exception as error: print(f'{red("Unknown error:")}\n{error}')


    @classmethod
    def _read_oid_list(cls) -> None:
        print('Reading oid_manufacturer.json file')
        FILE_PATH = os.path.dirname(os.path.abspath(__file__))
        FILE_PATH = os.path.join(FILE_PATH, 'oid_manufacturer.json')
        try:
            with open(FILE_PATH, 'r', encoding='utf-8') as file:
                cls.OID_LIST = json.load(file)
        except FileNotFoundError:  cls._sys_exit('File "oid_manufacturer.json not found"')
        except Exception as error: cls._sys_exit(f'Unknown error {error}')


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
        if varBinds:
            return Main._format_snmp_response(varBinds)
        return None


    @staticmethod
    def _format_snmp_response(varBinds:tuple) -> str:
        _, value = varBinds[-1]
        if isinstance(value, OctetString):
            return value.asOctets().decode("utf-8", errors="ignore")
        return value.prettyPrint()


    def _get_additional_information_if_possible(self) -> None:
        print('Getting manufacturer OID')
        thread_list = list()
        for ip in self._hosts:
            thread = threading.Thread(target=self._get_info_to_verify_connection, args=(ip,))
            thread_list.append(thread)
            thread.start()
        for thread in thread_list:
            thread.join()


    def _get_info_to_verify_connection(self, ip:str) -> str:
        response = self._execute_snmpget(ip, '.1.3.6.1.2.1.1.2.0')
        if response:
            self._set_data_for_thread(ip, response)
            self._get_info_using_snmp()
        else:
            with self._LOCK:
                self._unreacheable_hosts.append(ip)


    def _set_data_for_thread(self, ip:str, description:str) -> None:
        self._thread_local_var.ip          = ip
        self._thread_local_var.description = description


    def _get_info_using_snmp(self) -> None:
        self._get_manufacturer_oid_and_name()
        self._get_additional_information()


    def _get_manufacturer_oid_and_name(self) -> None:
        manufacturer_oid  = self._format_manufacturer_oid(self._thread_local_var.description)
        manufacturer_name = self._get_manufacturer_name_by_its_oid(manufacturer_oid)
        with self._LOCK:
            self._hosts[self._thread_local_var.ip] = {'manufacturer': manufacturer_name, 'oid': manufacturer_oid}


    @staticmethod
    def _format_manufacturer_oid(oid:str) -> str:
        oid = oid.split('=')[-1]
        oid = oid.split('.')[:7]
        oid = '.'.join(oid)
        return oid.strip()


    @classmethod
    @lru_cache(maxsize=10)
    def _get_manufacturer_name_by_its_oid(cls, oid:str) -> str:
        return cls.OID_LIST.get(oid, None)


    def _get_additional_information(self) -> None:
        description = self._execute_snmpget(self._thread_local_var.ip, '.1.3.6.1.2.1.1.1.0')
        oid_list    = self._get_oid_list(description.split()[0])
        self._hosts[self._thread_local_var.ip].update({'oids': oid_list})


    @classmethod
    @lru_cache(maxsize=10)
    def _get_oid_list(cls, description:str) -> list:
        oid_funtion = cls.MAPPING.get(description, None)
        if oid_funtion: return oid_funtion()


    def _remove_hosts_without_response(self) -> None:
        print('Removing hosts without response')
        self._hosts = {ip: self._hosts[ip] for ip in self._hosts if not ip in self._unreacheable_hosts}


    def _sort_ip_addresses(self) -> None:
        self._hosts = dict(sorted(self._hosts.items(), key=lambda item: ipaddress.ip_address(item[0])))


    @staticmethod
    def _display_result(hosts) -> None:
        for ip in hosts:
            print(ip)
            print(hosts[ip])





if __name__ == "__main__":
    system = Main()
    system._execute()
