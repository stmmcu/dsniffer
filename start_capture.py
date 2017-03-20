from netmiko import ConnectHandler
import time
import ftplib

router_user='xxxx'
router_pwd='yyyy'

def capture_linux(host,user,pwd,intf,src_ip,dst_ip):
  device = {
  'device_type': 'linux',
  'ip': '{}'.format(host),
  'username': user,
  'password': pwd
  }

  cmd = 'sudo tcpdump -c 9000 -w host1.pcap -i '+intf+' src '+src_ip+' and dst '+dst_ip+' &'
  print cmd
  net1 = ConnectHandler(**device)
  result = net1.send_command_expect(cmd)
  print result

def export_linux(host,user,pwd,file_name):
  f = open('host1.pcap','wb')
  ftp=ftplib.FTP(host)
  ftp.login(user,pwd)
  ftp.retrbinary("RETR "+file_name, f.write)
  f.close()
  
def capture_routers(routers,user,pwd):
  for router in routers:
    device = {
      'device_type': 'cisco_ios',
      'ip': '{}'.format(router),
      'username': user,
      'password': pwd,
      'secret':   pwd
    }
    cmd0 = 'monitor capture CAP1 clear'
    cmd1 = 'monitor capture CAP1 start'
    cmd2 = 'monitor capture CAP1 stop'
    net1 = ConnectHandler(**device)
    result = net1.send_command(cmd2)
    result = net1.send_command(cmd0)
    print 'starting capture on router {}'.format(router)
    result = net1.send_command(cmd1)

def export_from_router(routers,user,pwd):
  for router in routers:
    device = {
      'device_type': 'cisco_ios',
      'ip': '{}'.format(router),
      'username': user,
      'password': pwd,
      'secret':   pwd
    }
    print "stopping capture on router {}".format(router)
    cmd1 = 'monitor capture CAP1 stop'
    net1 = ConnectHandler(**device)
    result = net1.send_command(cmd1)
    print result

  index = 0
  for router in routers:
    index += 1
    file_name = "router" + str(index) + ".pcap"
    device = {
      'device_type': 'cisco_ios',
      'ip': '{}'.format(router),
      'username': user,
      'password': pwd,
      'secret':   pwd
    }
    export_host_user = 'xxx'
    export_host_pwd = 'yyy'
    export_host_ip = '172.16.118.88' 
    cmd2 = 'monitor capture CAP1 export ftp://' + export_host_user + ':' + export_host_pwd + '@' + export_host_ip + '/scripts/' + file_name
    net1 = ConnectHandler(**device)
    net1.enable()
    result = net1.send_command_expect(cmd2)
    time.sleep(1)
    print result

def capture_main(sniffer_hosts,routers,files,src_ip,dst_ip):
  for host in sniffer_hosts:
      capture_linux(host['ip'],host['user'],host['pwd'],host['capture_intf'],src_ip,dst_ip)
  capture_routers(routers,router_user,router_pwd)
  print "wait 60 seconds for capture to complete"
  time.sleep(60)
  for host in sniffer_hosts:
      export_linux(host['ip'],host['user'],host['pwd'],host['file_name'])
  export_from_router(routers,router_user,router_pwd)

if __name__ == '__main__':
  capture_main(sniffer_hosts,routers,files,src_ip,dst_ip)

