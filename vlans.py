#!/usr/bin/env python
import sys, commands

def vlans(host):
    vlan_exclusions = ['1000','1001','1002', '1003', '1004', '1005','4094']
    vlan_list = []
    get_vlans = commands.getoutput("%s %s 1.3.6.1.4.1.9.9.46.1.3.1.1.2" %(prod_snmp_walk,host))
    for x,i in enumerate(get_vlans.split('\n')):
        vlan = i.split(' ')[0].split('.')[-1]
        if vlan not in vlan_exclusions:
            vlan_list.append(vlan)
    return vlan_list
