# log4j-shell-poc
A Proof-Of-Concept python application for log4shell [CVE-2021-44228] vulnerability.
Project originally forked from https://github.com/kozmer/log4j-shell-poc.

## Requirements:
```
pip install -r requirements.txt
```

## Usage:

* Start the script
```
python3 poc.py
```

* Start a netcat listener to accept reverse shell connection.
```
nc -lvnp {your_port}
```

## Disclaimer
This script was written only to be able to test the Log4Shell vulnerability (CVE-2021-44228). **Use this script only on targets on which you are authorized**
