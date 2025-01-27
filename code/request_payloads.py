# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVE_Project
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


def token_request_payload(user:str, password:str) -> dict:
    return {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": user,
            "password": password,
        },
        "id": 1,
    }
    

def all_hosts_request_payload(token:str) -> dict:
    return {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["hostid", "name"],
            },
            "auth": token,
            "id": 2,
        }


def information_request_payload(hostid:str, token:str) -> dict:
    return {
            "jsonrpc": "2.0",
            "method": "item.get",
            "params": {
                "output": ["itemid", "name", "lastvalue"],
                "hostids": hostid,
                "search": {
                    "name": "Software",
                },
            },
            "auth": token,
            "id": 3,
        }