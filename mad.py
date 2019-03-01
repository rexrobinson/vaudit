#!/usr/bin/env python
import sys, commands
import re
import urllib2, json, warnings
import requests
requests.packages.urllib3.disable_warnings()

clear = commands.getoutput('clear')
print clear

def get_parser():
    import argparse
    parser = argparse.ArgumentParser(
                                description='Missing Vlan Audit (MAD)')

    parser.add_argument('-a', 
                    type=int,
                    help='Core Account Number',
                    required=True)

    parser.add_argument('-d', 
                    choices = ['dfw','ord','iad','lon','fra','hkg','syd'],
                    type=str,
                    help='DC options are dfw  ord iad lon fra hkg syd',
                    required=True)

    parser.add_argument('-n', 
                    choices = ['public','exnet','servicenet'],
                    type=str,
                    help='Network type: Options are public enxnet or servicenet',
                    required=True)

    parser.add_argument('-e',type=str,help='email to send report to')

    return parser

args = get_parser().parse_args()

try:
    if re.match('^[^@\s]+@[^@\s]+\.[^@\s]+[^\s]',args.e):
        email = args.e
    else:
        print clear
        print '%s is is not a valid email address' %(args.e)
        sys.exit()
except (IndexError,ValueError,NameError,KeyError,TypeError) as e:
    email = None

whoami = commands.getoutput('whoami')
walk = 'snmpwalk -Oqv -v2c -<redacted>'
long_walk = 'snmpwalk -v2c -<<redacted>'
tab = '\t'
index_interface = []
exclusion = '0'+('1'*1023) # this is a formula that will create a 1024 bit string that matchs 'All Vlans'
vlan_exclusions = ['1','999','0000','1000','1001','1002','1003','1004','1005','4093','4094','Ethernet','Ethernet0','FastEthernet0','All Vlans']
hex_to_bin = {'0':'0000', '1':'0001', '2':'0010','3':'0011','4':'0100','5':'0101','6':'0110','7':'0111','8':'1000','9':'1001','A':'1010','B':'1011','C':'1100','D':'1101','E':'1110','F':'1111'}

###### WENDALL'S CUSTOM ANSI COLOR FUNCTION ############################################################################
def color(text,style,background,color):
    colors = {'black':30,'red':31,'green':32,'yellow':33,'blue':34,'purple':35,'cyan':36,'white':37}
    styles = {0:0,'bold':1,'underline':4,'blink':5,'inverse':7,'hidden':8}
    backgrounds = {0:0,'black':40,'red':41,'green':42,'yellow':43,'blue':44,'purple':45,'cyan':46,'white':47}
    return '\033[%s;%s;%sm%s\033[0m' %(styles[style], backgrounds[background], colors[color], text)

error1 = color('VLAN MISSING ON TRUNK','bold','red','white')
error2 = color('VLAN MISSING ON SWITCH','bold','red','white')
passed = color('PASSED','bold','green','white')


def vlans(host):
    ### function that provides the vlans configured on a switch via SNMPv2###
    vlan_list = []
    get_vlans = commands.getoutput("%s %s 1.3.6.1.4.1.9.9.46.1.3.1.1.2" %(long_walk,host))
    for x,i in enumerate(get_vlans.split('\n')):
        vlan = i.split(' ')[0].split('.')[-1]
        if vlan not in vlan_exclusions:
            vlan_list.append(vlan)
    return vlan_list

def pull_ints(account,dc,service):
    ### function that pulls edge ports based on account/dc/network from unify db###
    url = 'https://unify.rackspace.com/network_account_region_service.json?account=%s&region=%s&service=%s' %(account,dc,service)
    data = requests.get(url,verify=False)
    if data.status_code != 200:
        print 'The API is down or busy, please try again'
        sys.exit()
    data = data.json()[0]['payload']
    if len(data) == 0:
        print color('There are no interfaces for account %s in %s on %s' %(account,dc,service),'bold','black','yellow')
        sys.exit()
    return data

def trunk_links(account,dc,service):
    ### function that pulls trunk ports based on account/dc/network from unify db###
    url = 'https://unify.rackspace.com/network_account_service_uplink.ajax?account=%s&dc=%s&service=%s' %(account,dc,service)
    data = requests.get(url,verify=False)
    if data.status_code != 200:
        print 'The API is down or busy, please try again'
        sys.exit()
    data = data.json()
    if len(data) == 0:
        print color('There are no interfaces for account %s in %s on %s' %(account,dc,service),'bold','black','yellow')
        sys.exit()
    return data


def hex_vlan(hex):
    ### function that finds allowed vlans based on the HEX SNMPv2 output ###
    vlan_allow_list = []
    binary_vlans = []
    vlans = hex.split()
    for binary in vlans:
        for bit in binary:
            if bit in hex_to_bin:
                binary_vlans.append(hex_to_bin[bit])
    joined_array = "".join(binary_vlans)
    if joined_array == exclusion:
        return 'All Vlans'
    else:
        vlan_array = []
        for index,test_bit in enumerate(joined_array):
            if test_bit == '1':
                vlan_allow_list.append(str(index))
    return vlan_allow_list

##### Pulling Trunked VLANS and VLANS that exist on customer switches #####
problem_list = []
my_trunks = [x for x in trunks if re.match('aggr',x['remote_hostname'])]

trunk_vlan = {}
for x in my_trunks:
    trunk_vlan[x['local_hostname']] = x['local_hostname']
    get_my_vlans = commands.getoutput("%s %s 1.3.6.1.4.1.9.9.46.1.6.1.1.4.%s" 
        %(walk,x['remote_hostname'],x['remote_ifindex']))
    my_vlan = hex_vlan(get_my_vlans)
    trunk_vlan[x['local_hostname']] = {'aggr':x['remote_hostname'],'int':x['remote_interface'],'vlans':my_vlan}

switch_vlan = {}
for i in trunks:
    switch_vlan[i['local_hostname']] = i['local_hostname']
    get_switch_vlans = vlans(i['local_hostname'])
    switch_vlan[i['local_hostname']] = {'vlans':get_switch_vlans}


#problems = []
problems = {}
### iterate through customer edge ports to check for missing vlans ###
for interface in ints:
    #print 'Testing %s %s' %(interface['hostname'],interface['if_name'])
    line_protocol = commands.getoutput("%s %s 1.3.6.1.2.1.2.2.1.8.%s"
        %(walk,interface['hostname'],interface['if_index']))
    if line_protocol == '1':
        #### checks what vlans are configured on the edge port
        my_vlans = commands.getoutput("%s %s 1.3.6.1.4.1.9.9.68.1.2.2.1.2.%s" 
            %(walk,interface['hostname'],interface['if_index']))
        my_vlans = [str(my_vlans)]
        
        ### skipping this access port if vlan is parked/black hole ###
        if my_vlans[0] in vlan_exclusions:
            continue
        
        ### will match a trunk edge port which requires a different snmp query to find the vlans
        if re.match('[aA-zZ]+',my_vlans[0]):
            my_vlans = commands.getoutput("%s %s 1.3.6.1.4.1.9.9.46.1.6.1.1.4.%s" 
                %(walk,interface['hostname'],interface['if_index']))
            my_vlans = hex_vlan(my_vlans)
            
            ### skipping this trunk edge port if passing "all vlans" ###
            if my_vlans == 'All Vlans':
                continue

        try:
            on_switch = switch_vlan[interface['hostname']]['vlans']
            on_switch.append('1')
            on_trunk =  trunk_vlan[interface['hostname']]['vlans']
            ### Adding VLAN1 to switch and trunk
            try:
                on_switch.append('1')
                on_trunk.append('1')
            except AttributeError:
                pass
            for vlan in my_vlans:
                ### checking if vlans assigned to interface are on the upstream trunk ###
                if  vlan not in on_trunk and on_trunk != 'All Vlans' and vlan not in vlan_exclusions:
                    my_problem = {'problem':"vlan not on trunked to this switch",
                                'missing_vlan':vlan,
                                'problem_device':trunk_vlan[interface['hostname']]['aggr'],
                                'problem_interface':trunk_vlan[interface['hostname']]['int']}

                    if interface['hostname'] not in problems:
                        problems[interface['hostname']] = interface['hostname']
                        problems[interface['hostname']] = [{'problems':[]}]
                        problems[interface['hostname']][0]['problems'].append(my_problem)
                    else:
                        problems[interface['hostname']][0]['problems'].append(my_problem)
                
                
                ### checking if vlans assigned to interface are on the switch ###
                if vlan not in on_switch:
                    my_problem = {'problem':"vlan not on this switch",
                                'missing_vlan':vlan,
                                'problem_device':interface['hostname'],
                                'problem_interface':'vlan.dat'}
        
                    if interface['hostname'] not in problems:
                        problems[interface['hostname']] = interface['hostname']
                        problems[interface['hostname']] = [{'problems':[]}]
                        problems[interface['hostname']][0]['problems'].append(my_problem)
                    else:
                        problems[interface['hostname']][0]['problems'].append(my_problem)

        except KeyError:
            pass
