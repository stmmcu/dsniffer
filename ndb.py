import requests
import json
import pprint
import re
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

NDB='172.16.118.88'
ndb_user='xxxx'
ndb_pwd='yyyy'

ndb_data = [{
'filter_name' : 'filter1',
'connection_name' : "connection1",
'dest_device' : "Wireshark",
'incoming_port' : "48",
'incoming_switch' : "00:01:f8:72:ea:ae:66:80"}]

def create_new_filter(filter_name,src_ip,dst_ip):
    parameters = {
      "name": filter_name,
      "etherType": "0x0800",
      "vlanId": "",
      "vlanPriority": "",
      "datalayerSrc": "",
      "datalayerDst": "",
      "networkSrc": src_ip,
      "networkDst": dst_ip,
      "protocol": "",
      "tosBits": "",
      "transportPortSrc": "",
      "transportPortDst": "",
      "httpMethodId": "",
      "tcpOptionLength": "",
      "bidirectional": "false"
    }

    url = 'https://' + NDB + ':8443/controller/nb/v2/monitor/filter/' + filter_name
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    ret = requests.put(url, json=parameters, headers=headers, auth=HTTPBasicAuth(ndb_user,ndb_pwd), verify=False)
    if ret.status_code == 200 or ret.status_code == 201:
       print "filter {} has been created successfully".format(filter_name)
    else:
       print "unable to create the filter" 

def create_new_connection(connection_name,filter_name,incoming_port,incoming_switch,dest_device):
    p = dict()
    p["name"]=connection_name
    p["allowFilter"]=[filter_name]
    p["device"]=[dest_device]
    p["sourcePort"]= ["OF|" + str(incoming_port) + "@OF|" + incoming_switch]
    p["priority"]="100"
    p["stripVlan"]="false"
    p["installInHw"]="true"
    p["isDeny"]="false"

    url = 'https://' + NDB + ':8443/controller/nb/v2/monitor/rule/' + connection_name
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    ret = requests.put(url, json=p, headers=headers, auth=HTTPBasicAuth(ndb_user,ndb_pwd), verify=False)
    
    if ret.status_code == 200 or ret.status_code == 201:
       print "connection rule {} has been created successfully".format(connection_name)
    else:
       print "Unable to create the connection rule {}, exiting...".format(connection_name)
       exit()

def toggle_connections():
    url = 'https://' + NDB + ':8443/controller/nb/v2/monitor/rule/test1'
    ret = requests.post(url, auth=HTTPBasicAuth(ndb_user,ndb_pwd), verify=False)
    print ret

def get_connections():
    url = 'https://' + NDB + ':8443/controller/nb/v2/monitor/rules'
    ret = requests.get(url, auth=HTTPBasicAuth(ndb_user,ndb_pwd), verify=False)
    if ret.status_code == 404:
       return([])
    else:
       cons = ret.json()
       existing_connections = []
       for con in cons['rule']:
          existing_connections.append(con['name'])
       return(existing_connections)

def delete_connection(name):
    url = 'https://' + NDB + ':8443/controller/nb/v2/monitor/rule/' + name
    ret = requests.delete(url, auth=HTTPBasicAuth(ndb_user,ndb_pwd), verify=False)
    if ret.status_code == 204:
       print "existing connection rule {} was deleted successfully".format(name)
    else:
       print "failed to delete existing connection rule {}".format(name)


def ndb_main(src_ip,dst_ip):
    existing_connections = get_connections()
    for con in existing_connections:
        delete_connection(con)
    for ndb_info in ndb_data:
        create_new_filter(ndb_info['filter_name'],src_ip,dst_ip)
        create_new_connection(
           ndb_info['connection_name'],
           ndb_info['filter_name'],
           ndb_info['incoming_port'],
           ndb_info['incoming_switch'],
           ndb_info['dest_device']
        )

if __name__ == '__main__':
   ndb_main(src_ip,dst_ip)
