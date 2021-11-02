# Arcana


## VirusTotal API Key
1. To make use of the VirusTotal API, you will need to first sign up an account on VirusTotal with the following link: https://www.virustotal.com/gui/join-us
2. You will then need to copy the API key found on the VirusTotal account user menu.

![image](https://user-images.githubusercontent.com/72640752/139626297-f18068d6-d3e6-4734-8c8b-63cd93617869.png)

3. The user will then need to paste the API key into the following string found in virusTotalAPI.py
```
API_KEY = ""
```
IMPORTANT: VirusTotal will only allow limited scan requests for free accounts. Please upgrade to the premium VirusTotal API to increase the total requests you can make. 
## Required Libraries
- libewf-python
- pandas
- pypytsk3
- tabulate
- validators
- virustotal-python
## Installation
```
git clone https://github.com/afiqbusari7/Arcana
cd Arcana
pip install -r requirements.txt
```
