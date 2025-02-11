# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/CVEProbe
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


def rukus_oid() -> list:
    return [
        '.1.1.2.1.1.1.1.0',        # Device 
        '.1.1.3.1.1.1.1.1.3.1'     # Firmware version
        ]


def hpe_5130() -> list:
    return [
        '.1.3.6.1.2.1.47.1.1.1.1.7.2',    # Device serie
        '.1.3.6.1.2.1.47.1.1.1.1.13.2',   # Device model
        '.1.3.6.1.2.1.47.1.1.1.1.10.2'    # Software version
        ]
