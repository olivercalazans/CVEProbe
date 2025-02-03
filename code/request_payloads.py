# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVEProbe
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
    

def device_names_and_ip_payload(token:str) -> dict:
    return {
    "jsonrpc": "2.0",
    "method": "host.get",
    "params": {
        "output": ["host", "interfaces"],
        "selectInterfaces": ["ip"]
    },
    "auth": token,
    "id": 1
}