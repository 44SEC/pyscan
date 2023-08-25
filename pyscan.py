# Define a codificação do arquivo como UTF-8.
# -*- coding: utf-8 -*-


''' 1TDCG - 44SEC
Suellen Guedes Rufino
Rakel de Macedo Oliveira
João Victor Santos Alves
Felipe de Resende Madeira
Pedro Henrique Lima Vieira
'''


# Importando as bibliotecas e códigos necessários
import argparse
from mongodb import Insert_MongoDB
from scanners import Port_Scan_TCP, Port_Scan_UDP


# Função PyScan
def PyScan():
    
    # Cria um analisador de argumentos da linha de comando
    parser = argparse.ArgumentParser(description="Scan de portas usando Nmap e armazenando os dados no MongoDB")
    parser.add_argument("-t", "--target", required=True, help="IP alvo para scan")
    parser.add_argument("-p", "--ports", required=True, help="Portas a serem escaneadas (exemplo: 20-100)")
    
    # Analisa os argumentos da linha de comando
    args = parser.parse_args()

    # Guarda o IP de destino e as portas a serem escaneadas
    target_ip = args.target
    target_ports = args.ports

    # Realiza o scan de portas usando a função Port_Scan
    scan_results_udp = Port_Scan_UDP(target_ip, target_ports)
    scan_results_tcp = Port_Scan_TCP(target_ip, target_ports)

    # Formata os resultados udp do scan em um dicionário
    formatted_results_udp = {
        "target_ip": target_ip,
        "target_ports": target_ports,
        "protocol": "UDP",
        "scan_data": scan_results_udp
    }

    # Formata os resultados tcp do scan em um dicionário
    formatted_results_tcp = {
        "target_ip": target_ip,
        "target_ports": target_ports,
        "protocol": "TCP",
        "scan_data": scan_results_tcp
    }
    
    # Cria um dicionário para armazenar ambos os resultados (TCP e UDP)
    combined_results = {
        "target_ip": target_ip,
        "target_ports": target_ports,
        "scan_data": [formatted_results_tcp, formatted_results_udp]
    }

    # Insere os resultados formatados no MongoDB
    Insert_MongoDB(combined_results)


# Rodando a função PyScan
PyScan()

