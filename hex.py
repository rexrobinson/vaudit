def hex_vlan(hex):
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
                vlan_allow_list.append(index)
    return vlan_allow_list
