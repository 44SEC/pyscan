# Define a codificação do arquivo como UTF-8.
# -*- coding: utf-8 -*-

# Importando as bibliotecas e códigos necessários
import argparse
from mongodb import Insert_MongoDB
from scanner import Port_Scan


# Função Main
def Main():
    
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
    scan_results = Port_Scan(target_ip, target_ports)

    # Imprime as portas abertas e fechadas
    print("\n[*] Portas abertas:")
    for port, data in scan_results.items():
        print(f"[!] Porta: {port}, Serviço: {data['service']}, Protocolo: {data['protocol']}")

    # Formata os resultados do scan em um dicionário
    formatted_results = {
        "target_ip": target_ip,
        "target_ports": target_ports,
        "scan_data": scan_results
    }

    print('\n')
    print(formatted_results)

    # Insere os resultados formatados no MongoDB
    Insert_MongoDB(formatted_results)
    print("\n[+] Resultados do scan inseridos no MongoDB com sucesso!\n")


# Rodando a função Main
Main()

