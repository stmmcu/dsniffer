import dpkt
import pprint
import socket

files = []
src_ip = ''
dst_ip = ''

def get_pkt_info_from_files():
    #This function is to extract all packets from all files and save them into a list called pkt_info
    print files
    print src_ip
    print dst_ip

    pkt_infos = []
    for file in files:
        pkt_list={}
        pkt_list['file_name']=file
        pkt_list['pkt_headers']=[]
        f = open(file)
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
               continue
            ip = eth.data
            if ip.p==dpkt.ip.IP_PROTO_TCP:
               tcp = ip.data
               src_ip2 = socket.inet_ntoa(ip.src)
               dst_ip2 = socket.inet_ntoa(ip.dst)
               if src_ip2 == src_ip and dst_ip2 == dst_ip:
                  pkt={}
                  pkt['sport'] = tcp.sport
                  pkt['dport'] = tcp.dport
                  pkt['seq'] = tcp.seq 
                  pkt['ack'] = tcp.ack 
                  pkt['latency'] = -100
                  pkt['ts'] = ts
                  pkt['len']=len(tcp.data)
                  # Add this pkt to the pkt_headers list
                  pkt_list['pkt_headers'].append(pkt)
        f.close()
        pkt_infos.append(pkt_list)

    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(pkt_infos)
    return(pkt_infos)

def get_traffic_flows(pkt_infos):
    #This function will build a list of flows based on different src,dst tcp port
    pkt_flows=[]
    for pkt_info in pkt_infos:
        for pkt in pkt_info['pkt_headers']: 
            new_flow = [pkt['sport'],pkt['dport']]
            if new_flow not in pkt_flows:
               pkt_flows.append(new_flow)

    #print pkt_flows
    return(pkt_flows)

def get_first_pkt_per_flow(pkt_infos,pkt_flow):
    #First need to find the list of files that contains the flow
    #Then go through the files and find the initial match

    list_of_files_with_flow = [] 
    first_file_with_flow = -1 
    file_index = 0
    for pkt_info in pkt_infos:
        for pkt in pkt_info['pkt_headers']:
            if pkt['sport']==pkt_flow[0] and pkt['dport']==pkt_flow[1]:
               list_of_files_with_flow.append(pkt_info['file_name'])
               if first_file_with_flow == -1:
                  first_file_with_flow = file_index 
               break
        file_index += 1
    #print first_file_with_flow
    #print list_of_files_with_flow

    #Now we should have the list of files with the flow and also the first file with the flow
    if len(list_of_files_with_flow) == 1:
       print 'Only a single file contains the flow with src IP {} dst IP {} src port {} dst port {}, exiting...'.format(src_ip,dst_ip,pkt_flow[0],pkt_flow[1])
       exit(0)

    found = False
    for pkt1 in pkt_infos[first_file_with_flow]['pkt_headers']:
        match_count = 0
        if pkt1['sport'] != pkt_flow[0] or pkt1['dport'] != pkt_flow[1]:
           continue
        for pkt_info in pkt_infos:
            #If this file does not contain the flow or this is the first file that contains the flow, skip it
            if pkt_info['file_name'] not in list_of_files_with_flow or pkt_info['file_name'] == pkt_infos[first_file_with_flow]['file_name']:
               #print 'skipping file with name {}'.format(pkt_info['file_name'])
               continue 
            else:
               for pkt2 in pkt_info['pkt_headers']:
                   if pkt2['sport']==pkt1['sport'] and pkt2['dport']==pkt1['dport'] and pkt2['ack']==pkt1['ack'] and pkt2['seq']==pkt1['seq']:
                      #Found a match for original pkt
                      match_count += 1
                      break
        #Now if the match count equals to length of files with flow - 1 then we found the packet
        if match_count == len(list_of_files_with_flow) - 1:
           matched_pkt = [pkt1['seq'],pkt1['ack']]
           found = True 
           break

    if found == True:
       #print matched_pkt
       return(matched_pkt)
    else:
       print 'Unable to find a common packet in all files for flow src IP {} dst IP {} src port {} dst port {}, exiting...'.format(src_ip,dst_ip,pkt_flow[0],pkt_flow[1])
    

def get_last_pkt_per_flow(pkt_infos,pkt_flow):
    #First need to find the list of files that contains the flow
    #Then go through the files and find the initial match

    list_of_files_with_flow = []
    first_file_with_flow = -1
    file_index = 0
    for pkt_info in pkt_infos:
        for pkt in pkt_info['pkt_headers']:
            if pkt['sport']==pkt_flow[0] and pkt['dport']==pkt_flow[1]:
               list_of_files_with_flow.append(pkt_info['file_name'])
               if first_file_with_flow == -1:
                  first_file_with_flow = file_index
               break
        file_index += 1
    #print first_file_with_flow
    #print list_of_files_with_flow

    #Now we should have the list of files with the flow and also the first file with the flow
    if len(list_of_files_with_flow) == 1:
       print 'Only a single file contains the flow with src IP {} dst IP {} src port {} dst port {}, exiting...'.format(src_ip,dst_ip,pkt_flow[0],pkt_flow[1])
       exit(0)

    found = False
    index = len(pkt_infos[first_file_with_flow]['pkt_headers']) - 1
    while index >= 0:
        pkt1 = pkt_infos[first_file_with_flow]['pkt_headers'][index]
        match_count = 0
       
        if pkt1['sport'] != pkt_flow[0] or pkt1['dport'] != pkt_flow[1]:
           index = index - 1
           continue

        for pkt_info in pkt_infos:
            #If this file does not contain the flow or this is the first file that contains the flow, skip it
            if pkt_info['file_name'] not in list_of_files_with_flow or pkt_info['file_name'] == pkt_infos[first_file_with_flow]['file_name']:
               #print 'skipping file with name {}'.format(pkt_info['file_name'])
               continue
            else:
               index2 = len(pkt_info['pkt_headers']) - 1
               while index2 >= 0:
                   pkt2 = pkt_info['pkt_headers'][index2]
                   if pkt2['sport']==pkt1['sport'] and pkt2['dport']==pkt1['dport'] and pkt2['ack']==pkt1['ack'] and pkt2['seq']==pkt1['seq']:
                      #Found a match for original pkt
                      match_count += 1
                      break
                   index2 = index2 - 1
      
        #Now if the match count equals to length of files_with_flow - 1 then we found the packet in all files
        index = index - 1
        if match_count == len(list_of_files_with_flow) - 1:
           matched_pkt = [pkt1['seq'],pkt1['ack']]
           found = True
           break

    if found == True:
       #print matched_pkt
       return(matched_pkt)
    else:
       print 'Unable to find a common packet in all files for flow src IP {} dst IP {} src port {} dst port {}, exiting...'.format(src_ip,dst_ip,pkt_flow[0],pkt_flow[1])

def generate_pkt_count_report(pkt_infos,pkt_flow,first_pkt,last_pkt):
    for pkt_info in pkt_infos:
        count = 0
        total_data_length = 0
        for pkt in pkt_info['pkt_headers']:
            if pkt['sport']==pkt_flow[0] and pkt['dport']==pkt_flow[1] and pkt['seq']>=first_pkt[0] and pkt['ack']>=first_pkt[1] and pkt['seq']<=last_pkt[0] and pkt['ack']<=last_pkt[1]:
               count += 1
               total_data_length += pkt['len']
        print "--------------------------------------------------------------------------------"
        print "For flow with src port {} and dst port {}".format(pkt_flow[0],pkt_flow[1])
        print "Inside file {} the matched packet count is {}".format(pkt_info['file_name'],count) 
        print "Inside file {} total data length is {}".format(pkt_info['file_name'],total_data_length)


def find_duplicate_pkt(pkt_infos,sport,dport,seq,ack):
    is_duplicate=False
    for pkt_info in pkt_infos:
        duplicate_count = 0
        for pkt in pkt_info['pkt_headers']:
            if pkt['sport']==sport and pkt['dport']==dport and pkt['seq']==seq and pkt['ack']==ack:
               duplicate_count += 1
        if duplicate_count > 1:
           is_duplicate = True
           break
    return(is_duplicate)

def generate_pkt_latency_report(pkt_infos,pkt_flow,first_pkt,last_pkt):
    #print pkt_infos
    #First need to find the list of files that contains the flow
    #Then go through the files and find the initial match

    list_of_files_with_flow = []
    first_file_with_flow = -1
    file_index = 0
    for pkt_info in pkt_infos:
        for pkt in pkt_info['pkt_headers']:
            if pkt['sport']==pkt_flow[0] and pkt['dport']==pkt_flow[1]:
               list_of_files_with_flow.append(pkt_info['file_name'])
               if first_file_with_flow == -1:
                  first_file_with_flow = file_index
               break
        file_index += 1
    #print first_file_with_flow
    #print list_of_files_with_flow

    #Now we should have the list of files with the flow and also the first file with the flow
    if len(list_of_files_with_flow) == 1:
       print 'Only a single file contains the flow with src IP {} dst IP {} src port {} dst port {}, exiting...'.format(src_ip,dst_ip,pkt_flow[0],pkt_flow[1])
       exit(0)

    duplicate_count = 0
    for pkt1 in pkt_infos[first_file_with_flow]['pkt_headers']:
        if pkt1['sport'] != pkt_flow[0] or pkt1['dport'] != pkt_flow[1]:
           continue
        else:
           #Check to see if there are duplicated pkts in this flow
           if find_duplicate_pkt(pkt_infos,pkt1['sport'],pkt1['dport'],pkt1['seq'],pkt1['ack']):
              duplicate_count += 1
              continue
           #print 'pkt1 has seq {} ack {} sport {} dport {}'.format(pkt1['seq'],pkt1['ack'],pkt1['sport'],pkt1['dport'])
           for pkt_info in pkt_infos:
               #If this file does not contain the flow or this is the first file that contains the flow, skip it
               if pkt_info['file_name'] not in list_of_files_with_flow or pkt_info['file_name'] == pkt_infos[first_file_with_flow]['file_name']:
                  #print 'skipping file with name {}'.format(pkt_info['file_name'])
                  continue
               else:
                  #Needs to find match packet in this file and calculate the latency
                  index2 = 0
                  while index2 < len(pkt_info['pkt_headers']):
                      pkt2 = pkt_info['pkt_headers'][index2]
                      if pkt2['sport']==pkt1['sport'] and pkt2['dport']==pkt1['dport'] and pkt2['ack']==pkt1['ack'] and pkt2['seq']==pkt1['seq']:
                         #Found a match for original pkt, update the latency information
                         pkt2['latency'] = float(pkt2['ts']) - float(pkt1['ts'])
                         #print 'pkt 1 {} pkt2 {} latency {}'.format(pkt1['ts'],pkt2['ts'],pkt2['latency']) 
                         break
                      index2 = index2 + 1

    #Now we should have all the latency field updated for all files, time to generate the statistics
    print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    print "Found {} retransmited packets in flow with sport {} and dport {}".format(duplicate_count,pkt_flow[0],pkt_flow[1])
    print "Latency is not calculated for retransmited packets"

    for pkt_info in pkt_infos:
        if pkt_info['file_name'] not in list_of_files_with_flow or pkt_info['file_name'] == pkt_infos[first_file_with_flow]['file_name']:
               #print 'skipping file with name {}'.format(pkt_info['file_name'])
               continue
        else:
            file_name = pkt_info['file_name']
            count = 0
            total_latency = 0.0
            for pkt in pkt_info['pkt_headers']:
                if pkt['sport']==pkt_flow[0] and pkt['dport']==pkt_flow[1]:
                   if pkt['latency'] > -100:
                      #print 'packet latency is {}'.format(pkt['latency'])
                      count += 1
                      total_latency = total_latency + float(pkt['latency'])
            if count > 0:
               average_latency = total_latency/count

            # Now calculation is complete
            print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            print 'within file name {}'.format(file_name)
            print 'for flow with src port {} dst port {}'.format(pkt_flow[0],pkt_flow[1])
            print 'total number of packets with latency info is {}'.format(count)
            print 'average latency is {}'.format(average_latency) 

def pcap_main(files1,src_ip1,dst_ip1):
  global files
  global src_ip
  global dst_ip
  files = files1
  src_ip = src_ip1
  dst_ip = dst_ip1

  pkt_infos = get_pkt_info_from_files()
  pkt_flows = get_traffic_flows(pkt_infos)
  for pkt_flow in pkt_flows:
    #print pkt_flow
    first_pkt = get_first_pkt_per_flow(pkt_infos,pkt_flow)
    last_pkt = get_last_pkt_per_flow(pkt_infos,pkt_flow)
    generate_pkt_count_report(pkt_infos,pkt_flow,first_pkt,last_pkt)
    generate_pkt_latency_report(pkt_infos,pkt_flow,first_pkt,last_pkt)
  exit()

if __name__ == '__main__':
  pcap_main(files,src_ip,dst_ip)

