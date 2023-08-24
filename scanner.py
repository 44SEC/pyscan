import nmap
import json

# A porta padrão da FIWARE é a 1026 e a do PhpMyAdmin é 3306
ip = '108.158.137.101' 
p_range = '21-100'
scan_results = {}

def scans(ip, p_range):
    nm = nmap.PortScanner()

    # Executando scan TCP
    custom_args_tcp = f"-p {p_range} -T4 -A -sS"
    nm.scan(hosts=ip, arguments=custom_args_tcp)

    # Executando scan UDP
    custom_args_udp = f"-p U:{p_range} -T4"
    nm_udp = nmap.PortScanner()
    nm_udp.scan(hosts=ip, arguments=custom_args_udp)

    # Transformando a saída em JSON

    # Criando um dicionário para os resultados do scan TCP e fazendo um for para que neste dicionário seja guardado, por host, somente as portas abertas
    tcp_results = {}
    for host in nm.all_hosts():
        open_ports = {port: "open" for port, info in nm[host]['tcp'].items() if info['state'] == 'open'}
        tcp_results[host] = open_ports

    # Criando um dicionário para os resultados do scan em UDP e fazendo o mesmo
    udp_results = {}
    for host in nm_udp.all_hosts():
        if 'udp' in nm_udp[host] and 'udp' in nm_udp[host]['udp']: # Esse if checa se há UDP no resultado do NMAP, sem isso o programa dá erro
            open_ports = {port: "open" for port in nm_udp[host]['udp'] if nm_udp[host]['udp'][port]['state'] == 'open'}
            udp_results[host] = open_ports

    # Adicionando no dicionário final os resultados
    scan_results["TCP Scan:"] = tcp_results
    scan_results["UDP Scan:"] = udp_results

# Criando a função principal do programa que irá executar o scan e imprimir na tela para o usuário

def main():

    #ip = input(str('[?] Insira o IP do alvo desejado: '))
    #p_range = input(str('[?] Insira o range de portas, separados por um hífen, ou vírgula caso seja duas ou mais portas específicas (ex: 21-443): '))
    ports_opened = []
    scans(ip, p_range)
    for port in p_range:
        if port in scan_results:
            print(f'[!] Porta {port} aberta')
            ports_opened.append(port)

        else:
            print(f'[!] A porta {port} está fechada')

    print(f'[+] O host {ip} possuí as portas {ports_opened} abertas')

main()

