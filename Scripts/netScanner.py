#!/usr/bin/env Python3

from pwn import *
import re, sys, time, nmap

### ---- COLORS ----- ###
correct = "\x1b[0;32m[+]\x1b[0m "
fail = "\x1b[0;31m[!]\x1b[0m "
warning = "\x1b[0;33m[*]\x1b[0m "
info = "\x1b[0;35m[i]\x1b[0m "
end = "\x1b[0m"

# Help message 
def helpMessage():
    print("""
    Para usar este script debes indicar una direccion ip o un rango de ips para escanear

    python3 netScanner.py <direccion_ip>        * Para escanear un host especifico
    python3 netScanner.py <rango_ips>           * Para escanear un rango de ips

    Ejemplo:
        python3 netScanner.py 192.168.0.14
        python3 netScanner.py 192.168.0.0/24

    NOTA: Ten en cuenta que cuanta que cuanto mas grande sea el rango, mas tardara el
    escaneo, se paciente
    """)

# Function to scan host and show open ports with services.
def hostScan(ip):
    bar = log.progress("Escaneando")
    bar.status(f"Escaneando el host {ip}...")
    scan = nm.scan(ip, arguments='-sS --open --min-rate 5000 -n -Pn')
    ports = []
    try:
        for port in nm[ip]['tcp'].keys():
            ports.append(port)
        str_ports = str(ports)
        bar1.status(f"Puertos {str_ports} en el host {ip}...")
        portScan = nm.scan(ip, str_ports, arguments='-sCV ')

        # Mostrar informacion
        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = nm[host][proto].keys()
                for port in lport:
                    print('port : %s\tname : %s\tservice : %s\tversion : %s' % (port, nm[host][proto][port]['name'], nm[host][proto][port]['product'], nm[host][proto][port]['version']))
                    
    except:
        print(f"{info}No se detectaron puertos abiertos en {ip}.")
    bar.success(f"Escaneo de {ip} completado.")

#input_string = sys.argv[1]
nm = nmap.PortScanner()
check_ip = r"^\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}$"
check_range = r"^\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}\/\d{0,2}$"
try:
    if re.match(check_ip, sys.argv[1]):
        ip = sys.argv[1]
        hostScan(ip)

    elif re.match(check_range, sys.argv[1]):
        rango = sys.argv[1]
        bar = log.progress("Probando")
        bar.status(f"Probando todos los host en la red {rango}")
        nm.scan(hosts=rango, arguments='-n -sP -PE')
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        bar.success("Prueba de hosts terminada.")
        for host, status in hosts_list:
            hostScan(host)

    else:
        print(f"{fail}Direccion ip incorrecta")
except:
    print(f"{fail}Debes introducir una direccion IP")
    helpMessage()

