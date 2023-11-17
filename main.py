from scapy.all import sniff, IP, TCP, DNS
import subprocess
import threading
from datetime import datetime

valid_ports = {80, 25, 53, 110, 143, 443, 3389, 3306, 5432, 8080, 8443} ##http, smtp, dns, pop3, imap, https, MySQL, PostgreSQL, http proxy, https proxy
valid_size = 1024 ## узанется путем мониторинга трафика на действующем приложении

valid_dns_symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

night_ip = {}

def clear_dict(key):
    night_ip[key] = 0

def ban(ban_ip):
    command = ["sudo", "iptables", "-A", "INPUT", "-s", ban_ip, "-j", "DROP"]
    subprocess.run(command)

def unban(ip):
    command = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(command)

def log(ip, date, reason, level):
    str = f"{date}: banned {ip}, because {reason}"
    with open('log.log', 'a') as f:
        if level == "warning":
            f.write("WARNING : " + str)
        if level == "ban":
            f.write("BAN : " + str)
            ban(ip)
        if level == "time_ban":
            f.write("TIME_BAN : " + str)
            ban(ip)
            ban_timer = threading.Timer(18000, unban, args = ip)
            ban_timer.start()

def is_night_traffic(time):
    now_time = datetime.now()
    hour = now_time.hour
    if 0 <= hour <= 6:
        return True

def check_for_strange_DNS(packet):
    dns_name = packet.qd.qname.decode()
    for char in dns_name.upper():
        if char not in valid_dns_symbols:
            return False
    if len(dns_name) > 64:
        return False
    
def work_with_dict(ip):
    if night_ip.get(ip) != None:
        night_ip[ip] += 1
        if night_ip[ip] > 20:
            log(ip, datetime.now(), "too many night requests", "time_ban")
    else:
        night_ip[ip] = 0
        night_ip_timer = threading.Timer(60, clear_dict, args=ip)
        night_ip_timer.start()

def check_for_non_valid_traffic(packet):

    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        request_size = len(packet[TCP].payload)

        if len(set([src_ip, dst_ip])) > 1:
            log(src_ip, datetime.now(), "different source and destination ip adress", "ban")
        if dst_port not in valid_ports:
            log(src_ip, datetime.now(), "non valid port", "ban")
        if request_size > valid_size:
            log(src_ip, datetime.now(), "request too big", "warning")
        if is_night_traffic == True:
            work_with_dict(src_ip)

    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        src_ip = packet[IP].src
        if check_for_strange_DNS(dns_layer) == False:
            log(src_ip, datetime.now(), "strange DNS request", "ban")
try:
    sniff(prn=check_for_non_valid_traffic, store=0)
except KeyboardInterrupt:
    print("Exit with Keyboard")
