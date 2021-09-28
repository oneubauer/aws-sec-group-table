# aws-sec-group-table

Just a simple script that makes looking at an AWS security group a little easier.

usage:

[with optional highlighting of CIDRs that contain a list of networks:

`aws ec2 describe-security-groups | ./sec-group-table.py [--netlist 192.168.0.0/24 172.0.0.0/8]`
