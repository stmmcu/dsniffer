from netmiko import ConnectHandler
import re
import time
import sys

device_type = 'cisco_ios'
router_user = 'xxxx'
router_pwd = 'yyyy'

def config_PCAP(dev,intf,src_ip,dst_ip):
  device = {
    'device_type': device_type,
    'ip': '{}'.format(dev),
    'username': router_user,
    'password': router_pwd,
    'secret': router_pwd 
  }

  net1 = ConnectHandler(**device)
  output1 = net1.enable()
  net1.send_command('config t')
  net1.send_command('no ip access-list extended CAP1')
  net1.send_command('ip access-list extended CAP1')
  cmd = 'permit ip host ' + src_ip + ' host ' + dst_ip
  net1.send_command(cmd)
  net1.send_command('end')
  net1.send_command('no monitor capture CAP1')
  net1.send_command('monitor capture CAP1 buffer size 5')
  net1.send_command('monitor capture CAP1 access-list CAP1')
  net1.send_command('monitor capture CAP1 limit packets 9000')
  cmd = 'monitor capture CAP1 interface ' + intf + ' both'
  net1.send_command(cmd)
  print "configured EPC on device {} interface {} for source IP {} and destination IP {}".format(dev,intf,src_ip,dst_ip)

def epc_main(routers,capture_intf,src_ip,dst_ip):
  index = 0
  while index < len(routers):
    router = routers[index]
    intf = capture_intf[index]
    config_PCAP(router,intf,src_ip,dst_ip)
    index += 1

if __name__ == '__main__':
  epc_main(routers,capture_intf,src_ip,dst_ip)
