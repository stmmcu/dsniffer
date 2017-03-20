import json
import requests
import re
import time

n7k_username='xxxx'
n7k_password='yyyy'

def nxapi_call(hostname, payload, username, password, content_type="json"):
  headers={'content-type':'application/%s' % content_type}
  response = requests.post("http://%s/ins" % (hostname),
  auth=(username, password),
  headers=headers,
  data=json.dumps(payload),
  timeout=4)
  if response.status_code == 200:
    # verify result if a cli_conf operation was performed
    if "ins_api" in payload:
      if "type" in payload['ins_api'].keys():
        if "cli_conf" in payload['ins_api']['type']:
          #print response.json()
          if type(response.json()['ins_api']['outputs']['output']) is list:
             for result in response.json()['ins_api']['outputs']['output']:
                if result['code'] != "200":
                   print("--> partial configuration failed, please verify your configuration!")
                   break
    return response.json()
  else:
     msg = "call to %s failed, status code %d (%s)" % (hostname,
         response.status_code,
         response.content.decode("utf-8"))
     print(msg)
     raise Exception(msg)

def nxapi_cli_show(show_command, hostname, username, password):
  payload = [
  {
    "jsonrpc": "2.0",
    "method": "cli",
    "params": {
    "cmd": show_command,
    "version": 1.2
    },
    "id": 1
  }
  ]
  return nxapi_call(hostname, payload, username, password, "json-rpc")

def nxapi_cli_conf(commands, hostname, username, password):
# convert the given configuration commands to a format which can be used within the Cisco NX-API and verify
# that the configuration script does not end with the termination sign (lead to an error in the last command)
  commands = commands.replace("\n"," ; ")
  if commands.endswith(" ; "):
    commands = commands[:-3]
  #print commands

  payload = {
      "ins_api": {
      "version": "1.2",
      "type": "cli_conf",
      "chunk": "0", # do not chunk results
      "sid": "1",
      "input": commands,
      "output_format": "json"
      }
  }
  return nxapi_call(hostname, payload, username, password, "json")

def check_existing_span(switch,span_id):
  cmd = "show monitor session " + str(span_id)
  try:
     result = nxapi_cli_show(cmd, switch, n7k_username, n7k_password)
     if result['result']['body']['TABLE_session']['ROW_session'] is not None:
        print "SPAN session {} already exists".format(span_id)
        return True
     else:
        print "SPAN session {} does not exist".format(span_id)
        return False
  except:
     print "SPAN session {} does not exist".format(span_id)
     return False

def find_ip_next_hop_interface(switch,dst_ip):
  cmd = "show ip route " + dst_ip
  result = nxapi_cli_show(cmd, switch, n7k_username, n7k_password)
  if result['result']['body']['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path'] is not None:
     next_hop_intf =  result['result']['body']['TABLE_vrf']['ROW_vrf']['TABLE_addrf']['ROW_addrf']['TABLE_prefix']['ROW_prefix']['TABLE_path']['ROW_path']['ifname']
     print "Next hop for IP address {} is {}".format(dst_ip,next_hop_intf)
     return(next_hop_intf)
  else:
     print "Unable to find next hop interface for IP address {}".format(dst_ip)
     return

def remove_existing_span(switch,session_number):
  cmd = "no monitor session " + str(session_number)
  cmd = cmd + "\nexit"
  result = nxapi_cli_conf(cmd, switch, n7k_username, n7k_password)
  print "monitor session {} has been removed".format(session_number)
  #print result

def create_new_span(switch,src_intf,dest_intf,session_number):
  cmd = "monitor session " + str(session_number) + "\nsource interface " + src_intf + " tx\ndestination interface " + dest_intf + "\nno shut"
  ##print cmd
  result = nxapi_cli_conf(cmd, switch, n7k_username, n7k_password)
  print "monitor session {} has been created successfully".format(session_number)
  #print result
 
def span_main(n7k_sw,src_ip,dst_ip,span_dest_intf,span_sess_num):
  print("----------------------------------------")
  print("start the span configuration script")
  print("----------------------------------------")

  for switch in n7k_sw:
    if check_existing_span(switch,span_sess_num) == True:
      remove_existing_span(switch,span_sess_num)
    span_src_intf = find_ip_next_hop_interface(switch,dst_ip)
    if switch in span_dest_intf:
       dest_intf = span_dest_intf[switch]
    else:
       print "switch {} does not have destination interface defined, exiting...".format(switch)
       exit()
    create_new_span(switch,span_src_intf,dest_intf,span_sess_num)

if  __name__ == "__main__":
  span_main(n7k_sw,src_ip,dst_ip,span_dest_intf,span_sess_num)
