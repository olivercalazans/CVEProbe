# CVEProbe
The project is a system that integrates with Zabbix to collect detailed information about hardware, software, and manufacturers in the monitored infrastructure. It then searches the internet for known vulnerabilities (CVEs) related to these components, providing an automated way to identify potential security risks and improve the organization's cybersecurity posture.

<br>

## Dependencies
This project requires two external dependencies: the ```requests``` and ```PySNMP``` libraries. It is important to use Python 3.11, as PySNMP relies on libraries like pyasn1, which are not compatible with Python 3.12.

<br>

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
