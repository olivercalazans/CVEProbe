# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVE_Mapper
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


def create_a_dict(device:str, soft_version=None, so=None) -> dict:
    return {'device': device, 'version': soft_version, 'so': so}


def hp_printers(description:str) -> dict:
    try:    return hp_laser_string_extractor(description)
    except: return description


def hp_laser_string_extractor(description:str) -> dict:
    description = description.split(';')
    return [description[0], description[1].split()[0]]


def aruba_switch_string_extractor(description:str) -> dict:
    description      = description.split(',')[0]
    device_name      = description.split('Switch')[0].strip()
    software_version = description.split('Version')[1].strip()
    return create_a_dict(device_name, software_version)


def hp_switch_string_extractor(description:str) -> dict:
    device_name      = description.split('\n')[1]
    description      = description.split('\n')[0].split(',')
    sys_operational  = description[0]
    software_version = description[1].split()[-1]
    return create_a_dict(device_name, software_version, sys_operational)