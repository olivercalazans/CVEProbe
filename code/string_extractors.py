# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVE_Mapper
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


def create_a_dict(device:str, softversion:str) -> dict:
    return {'device': device, 'softversion': softversion}


def hp_printers(description:str) -> dict:
    try:    return hp_laser_string_extractor(description)
    except: return description


def hp_laser_string_extractor(description:str) -> dict:
    description = description.split(';')
    return description[0], description[1].split()[0]


def aruba_switch_string_extractor(description:str) -> dict:
    description = description.split('Switch')
    device      = description[0].strip()
    software    = description[1].split('Version')[1]
    software    = software.split(',')[0].strip()
    return device, software
