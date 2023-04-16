import sys
import csv
from ipaddress import IPv4Address, IPv4Network
import ipaddress

# 获取命令行参数中的文件名
if len(sys.argv) < 2:
    print("Please provide a filename as command line argument.")
    exit()

filename = sys.argv[1]

# 用字典来记录每个区域的IP地址列表
ip_dict = {}

with open(filename, newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        area = row['Area'].strip()
        if area != '':
            ip = IPv4Address(row['IP'])
            if area not in ip_dict:
                ip_dict[area] = [ip]
            else:
                ip_dict[area].append(ip)

# 输出非空Area有多少个IP地址
for area in sorted(ip_dict.keys()):
    ips = ip_dict[area]
    cidrs = []
    while len(ips) > 0:
        # 将连续的IP地址合并成CIDR形式
        start_ip = end_ip = IPv4Address(ips[0])
        for i in range(1, len(ips)):
            if ips[i] == end_ip + 1:
                end_ip = IPv4Address(ips[i])
            else:
                break
        try:
            cidr = [ipaddr for ipaddr in ipaddress.summarize_address_range(start_ip, end_ip)]
            cidrs.append(cidr)
        except ValueError as e:
            print(f"Error: {e}")
            print(f"start_ip={start_ip}, end_ip={end_ip}")
            print(f"ips={ips}, len(cidrs)={len(cidrs)}")
            exit()
        ips = ips[len(cidr):]

    print(f"{area}: {len(cidrs)}")
    # print(f"{area}: {', '.join(str(';'.join([a.with_prefixlen for a in c])) for c in cidrs)}")
