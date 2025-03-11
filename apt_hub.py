#!/usr/bin/Python3
#Author: Shilpesh Trivedi
#Email: tshilpesh@gmail.com

import os
import sys
import json
import time
import base64
import argparse
import requests
import datetime
from shutil import rmtree

class apt_hub(object):

        def __init__(self):
                
                self.key = "" #Enter Your malpedia API Key Here
                self.base = "https://malpedia.caad.fkie.fraunhofer.de"
                self.otx_headers = {
                'X-OTX-API-KEY': "", # Enter Your OTX API KEY here
                }
                self.mitre = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"

        def get_apt_details_malpedia(self,TAName,path):

                url = '/api/get/actor/'
                apt_list = '/api/list/actors'
                sample = '/api/list/samples/'
                sample_dowload = '/api/get/sample/'
                yara = '/api/get/yara/'
                yara_path = path+'yara'
                sample_path = path+'sample'
                header = {'Authorization' : 'apitoken '+self.key}
                data = requests.get(self.base+apt_list,headers=header)
                apt_list_json_data = json.loads(data.text)
                count = 0

                if TAName.lower() in apt_list_json_data:
                        apt_data = requests.get(self.base+url+TAName,headers=header)
                        apt_json_data = json.loads(apt_data.text)
             
                if TAName.lower() not in apt_list_json_data:
                        
                        for apt_name in apt_list_json_data:
                                count +=1
                                
                                if count % 60 == 0:
                                        time.sleep(20)
                                apt_data = requests.get(self.base+url+apt_name,headers=header)
                                apt_json_data = json.loads(apt_data.text)

                                if 'meta' in apt_json_data:
                                        if 'synonyms' in apt_json_data['meta']:
                                                aka = apt_json_data['meta']['synonyms']
                                                if (TAName in aka) or (TAName.lower() in aka) or (TAName.upper() in aka) or (TAName.title() in aka):
                                                        TAName = apt_name
                                                        break

                apt_data = requests.get(self.base+url+TAName,headers=header)
                apt_json_data = json.loads(apt_data.text)
                file = path+TAName+'_malpedia_profile.json'

                with open(file,'w') as f:
                        json.dump(apt_json_data, f)

                print("\n[*] APT details from malpedia written on:'{}'".format(file))

                if 'detail' not in apt_json_data:

                        os.makedirs(yara_path)
                        os.makedirs(sample_path)

                        print ("\n[*] Colleting malware samples & YARA associated with '{}' from malpedia".format(TAName))

                        for families in apt_json_data['families']:
                                families_data = requests.get(self.base+sample+families,headers=header)
                                json_sha256_data = json.loads(families_data.text)

                                for sha256 in json_sha256_data:
                                        sample_sha256 = sha256['sha256']
                                        dwnld_sample = requests.get(self.base+sample_dowload+sample_sha256+'/zip',headers=header)

                                        if dwnld_sample.status_code == 200:
                                                json_dwnld_sample = json.loads(dwnld_sample.text)
                                                if sys.platform == 'win32':
                                                        open(sample_path+'\\'+sample_sha256+'{}.zip'.format(families), "wb").write(base64.b64decode(json_dwnld_sample['zipped']))
                                                else:
                                                        open(sample_path+'/'+sample_sha256+'({}).zip'.format(families), "wb").write(base64.b64decode(json_dwnld_sample['zipped']))
                                        time.sleep(1)
                                yara_req = requests.get(self.base+yara+families+'/zip',headers=header)

                                if yara_req.content != b'None':
                                        if sys.platform == 'win32':
                                                open(yara_path+'\\'+'{}_yara.zip'.format(families), "wb").write(yara_req.content)
                                        else:
                                                open(yara_path+'/'+'{}_yara.zip'.format(families), "wb").write(yara_req.content)
                                                
                        print("\n\t[-] All malware samples associated '{}' dowloaded at '{}', PASSWORD is 'infected'".format(TAName,sample_path))
                        print("\n\t[-] All YARA associated '{}' dowloaded at '{}'".format(TAName,yara_path))
                else:
                        print("[!] No information about '{}' was found on Malpedia".format(TAName))

                return TAName

        def get_apt_details_otx(self,TAName,path):

                today = datetime.date.today()
                year = today.year
                fina_pulses_id = []
                from_to_date = []
                indicators = path+'indicators'
                os.makedirs(indicators)

                print ("[*] Colleting indicators associated with '{}'".format(TAName))

                for i in range(1,30):
                        params = {
                        'sort': 'created',
                        'q': TAName+' '+str(year),
                        'page':i,
                        'limit':'50'
                        }

                        response = requests.get('https://otx.alienvault.com/api/v1/search/pulses', headers=self.otx_headers, params=params)
                        result = response.json()
                        result_data = result['results']
                        final_len =len(result_data)+1

                        if len(result_data) == 0:
                                break

                        if i>=final_len:
                                break

                        for otx_data in result_data:
                                created_at = otx_data['created']
                                modified_at = otx_data['modified']
                                pulses_id = otx_data['id']

                                if str(year) in created_at:
                                        fina_pulses_id.append(pulses_id)

                if len(fina_pulses_id) != 0:
                        print ('\t[+] Indicator found:\n')
                        indicators_path = indicators+'/'

                        if sys.platform == 'win32':
                                indicators_path = indicators+'\\'

                        all_in_one_csv = indicators_path+'all_in_one_indicators.csv'
                        all_in_one = open(all_in_one_csv,'a')
                        all_in_one.write('Date,Title,Type,Indicator\n')

                        for pulses_id in fina_pulses_id:
                                file = indicators_path+pulses_id+'_indicators.json'
                                response = requests.get('https://otx.alienvault.com/api/v1/pulses/{}'.format(pulses_id), headers=self.otx_headers,timeout=30)
                                result = response.json()

                                if TAName.lower() in result['name'].lower() or TAName.lower() in result['description'].lower():
                                        with open(file, 'w') as f:
                                                for ioc in result['indicators']:
                                                        tmp_date = ioc['created'].split('T')
                                                        date = tmp_date[0]
                                                        ind_type = ioc['type'].replace('FileHash-','')
                                                        indicator = ioc['indicator']
                                                        from_to_date.append(date)
                                                        all_in_one.write(date+','+result['name']+','+ind_type+','+indicator+'\n')
                                                        
                                                json.dump(result, f)
                                        print ("\t\t[-] Indicators written:'{}'".format(file))

                        from_to_date = sorted(from_to_date, reverse=True)
                        print ("\n\t[!] All indicators from '{}' to '{}' written at:'{}'\n".format(from_to_date[-1],from_to_date[0],all_in_one_csv))
                else:
                        print ('\t[!] No indicator are found for {}:\n'.format(TAName))

        def get_apt_mitre_profile_ttp(self,TAName,path):

                TAName = apt_hub().get_apt_details_malpedia(TAName,path)
                response = requests.get(self.mitre)
                result = response.json()
                mitre_ids = []
                get_ta = open(path+TAName+'_malpedia_profile.json').read()
                get_ta_json = json.loads(get_ta)
                mitre_profile = path+TAName+'_mitre_profile.json'
                mitre_ttps = path+TAName+'_mitre_ttps.json'

                if 'meta' in get_ta_json:
                        ta_ids = get_ta_json['meta']['synonyms']
                        
                        for ta_id in ta_ids:
                                if ta_id.startswith('G0'):
                                        mitre_ids.append(ta_id)

                        if len(mitre_ids) != 0:
                                mitre_object = result['objects']

                                for mitre_data in mitre_object:
                                        if mitre_data['type']=='intrusion-set':
                                                for external_id in mitre_data['external_references']:
                                                        for ta_mitre_id in mitre_ids:
                                                                if 'external_id' in external_id and ta_mitre_id == external_id['external_id']:
                                                                        with open(mitre_profile,'a') as f:
                                                                                json.dump(mitre_data, f)

                                print("\n[*] APT profile from ATTACK MITRE written on:'{}'".format(mitre_profile))

                                for ta_mitre_id in mitre_ids:
                                        response = requests.get("https://attack.mitre.org/groups/{}/{}-enterprise-layer.json".format(ta_mitre_id,ta_mitre_id))
                                        result = response.json()

                                        with open(mitre_ttps,'a') as f:
                                                json.dump(result, f)

                                print("\n[*] APT's TTPs from ATTACK MITRE written on:'{}'\n".format(mitre_ttps))
                        else:
                                mitre_object = result['objects']
                                for mitre_data in mitre_object:
                                        if mitre_data['type']=='intrusion-set':
                                                if TAName.lower() == mitre_data['name'].lower():
                                                        with open(mitre_profile,'a') as f:
                                                                json.dump(mitre_data, f)

                                                        for Group_ID in mitre_data['external_references']:
                                                                if 'external_id' in Group_ID:
                                                                        Group_ID = Group_ID['external_id']
                                                                        response = requests.get("https://attack.mitre.org/groups/{}/{}-enterprise-layer.json".format(Group_ID,Group_ID))
                                                                        result = response.json()
                                                                        with open(mitre_ttps,'a') as f:
                                                                                json.dump(result, f)

                                                        print("\n[*] APT profile from ATTACK MITRE written on:'{}'".format(mitre_profile))
                                                        print("\n[*] APT's TTPs from ATTACK MITRE written on:'{}'\n".format(mitre_ttps))
                else:
                        print("[!] No information about '{}' on ATTACK MITRE".format(TAName))

if __name__ == '__main__':

        print("   _____ _____________________ .__         ___.    ")
        print("  /  _  \\______   \\__    ___/  |  |__  __ _\\_ |__  ")
        print(" /  /_\\  \\|     ___/ |    |    |  |  \\|  |  \\ __ \\ ")
        print("/    |    \\    |     |    |    |   Y  \\  |  / \\_\\ \\")
        print("\\____|__  /____|     |____|    |___|  /____/|___  /")
        print("        \\/                          \\/          \\/ ")
        print("\n\t                              [*] Threat Actor Lookup [Profile/MITRE TTP's/IOC's (Current Year)]")
        print("\t                              [*] Author: Shilpesh Trivedi",'\n')
        print("\t                              [!] NOTE: THIS SCRIPT TAKES TIME TO COLLECT ALL INFO ABOUT APT PLZ BE PATIENT :)",'\n')

        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--search",
                        required=True,
                        default=None,
                        help="Required APT name for search")

        args = parser.parse_args()

        if os.path.isdir(args.search) == True:
                rmtree(args.search)
                os.makedirs(args.search)
        else:
                os.makedirs(args.search)

        path = args.search+'/'

        if sys.platform == 'win32':
                path = args.search+'\\'

        try:
                apt_hub().get_apt_mitre_profile_ttp(args.search,path)
                apt_hub().get_apt_details_otx(args.search,path)

        except KeyboardInterrupt:
                print("\n\t [!] You have cancelled the '{}' search\n".format(args.search))
