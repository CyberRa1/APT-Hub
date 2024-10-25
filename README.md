# APT-Hub
APT hub, It help's research to collect information and data on the latest APT activities. It collects following data on give APT name

- APT profiles (Malpedia, MITRE)
- IOCs of current year (otx.alienvault)
- Publish blogs on APT
- MITRE TTPs (ATTACK MITRE)

PS: This script requires Python 3 and mandates an API key from Malpedia and otx.alienvault, both of which are free to obtain.

# Usage

apt_hub.py -s [apt name]

   _____ _____________________ .__         ___.    
  /  _  \______   \__    ___/  |  |__  __ _\_ |__  
 /  /_\  \|     ___/ |    |    |  |  \|  |  \ __ \ 
/    |    \    |     |    |    |   Y  \  |  / \_\ \
\____|__  /____|     |____|    |___|  /____/|___  /
        \/                          \/          \/ 

	                              [*] Threat Actor Lookup [Profile/MITRE TTP's/IOC's (Current Year)]
	                              [*] Author: Shilpesh Trivedi 

	                              [!] NOTE: THIS SCRIPT TAKES TIME TO COLLECT ALL INFO ABOUT APT PLZ BE PATIENT :) 

usage: apt_hub.py [-h] -s SEARCH

optional arguments:
  -h, --help            show this help message and exit
  -s SEARCH, --search SEARCH
                        required APT name for search
