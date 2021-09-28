#!/bin/env python

import json
import sys
import ipaddress
import argparse



from tabulate import tabulate
from colorama import Fore
from colorama import Back
from colorama import  Style


cli=argparse.ArgumentParser()
cli.add_argument(  "--netlist",
                    nargs="*",
                    type=str,
                    default=[]
                )
cli.add_argument(   "--vpclist",
                    nargs="*",
                    type=str,
                    default=[]
                )

args = cli.parse_args()

data = json.load(sys.stdin)

table_data = []

def network_match_netlist(network):
    result = False
    target_network = ipaddress.ip_network(network)

    for net in args.netlist:
        test_network = ipaddress.ip_network(net)
        match = test_network.subnet_of(target_network)
        if test_network.subnet_of(target_network) == True:
            result = True
            break
    return result

for group in data['SecurityGroups']:
    if args.vpclist != [] and group['VpcId'] not in args.vpclist:
        continue
    groupName = group['GroupName']
    vpcId = group['VpcId']
    inUserIdString = ""
    inCidrString = ""
    outUserIdString = ""
    outCidrString = ""
    tagString = ""

    for ipPermissions in group['IpPermissions']:
        if "FromPort" in ipPermissions:
            if ipPermissions['FromPort'] == ipPermissions['ToPort']:
                portRange = f"{ipPermissions['FromPort']}"
            else:
                portRange = f"{ipPermissions['FromPort']}-{ipPermissions['ToPort']}"
        else:
            portRange = "any"

        if "IpProtocol" in ipPermissions:
            ipProtocolString = ipPermissions['IpProtocol']
        else:
            ipProtocolString = "any"

        for ipRange in ipPermissions['IpRanges']:
            if network_match_netlist(ipRange['CidrIp']) == True:
                inCidrString += f"{Back.RED}{ipRange['CidrIp']}{Style.RESET_ALL}:{ipProtocolString}:{portRange}\n"
            else:
                inCidrString += f"{ipRange['CidrIp']}:{ipProtocolString}:{portRange}\n"

        for userIdPair in ipPermissions['UserIdGroupPairs']:
            inUserIdString += f"u:{userIdPair['UserId']} g:{userIdPair['GroupId']}\n"

    for ipPermissions in group['IpPermissionsEgress']:
        if "FromPort" in ipPermissions:
            if ipPermissions['FromPort'] == ipPermissions['ToPort']:
                portRange = f"{ipPermissions['FromPort']}"
            else:
                portRange = f"{ipPermissions['FromPort']}-{ipPermissions['ToPort']}"
        else:
            portRange = "any"

        if "IpProtocol" in ipPermissions:
            ipProtocolString = ipPermissions['IpProtocol']
        else:
            ipProtocolString = "any"

        for ipRange in ipPermissions['IpRanges']:
            outCidrString += f"{ipRange['CidrIp']}:{ipProtocolString}:{portRange}\n"
        for userIdPair in ipPermissions['UserIdGroupPairs']:
            outUserIdString += f"u:{userIdPair['UserId']} g:{userIdPair['GroupId']}\n"

    if "Tags" in group:
        for tag in  group['Tags']:
            tagString += f"{tag['Key']}={tag['Value']}\n"

    row = [groupName, vpcId, inCidrString, inUserIdString, outCidrString, outUserIdString, tagString ]
    table_data.append(row)

print(tabulate(table_data,headers=["Group Name", "CIDR (IN)", "UserID (IN)", "CIDR (OUT)", "UserID (OUT)", "Tags"],tablefmt="fancy_grid"))



