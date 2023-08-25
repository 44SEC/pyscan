import nmap


# Função para realizar o scan de portas TCP e UDP
def Port_Scan(target_ip, target_ports):
    
    # Cria uma instância do scanner de portas Nmap
    nm = nmap.PortScanner()

    # Realiza o scan de portas TCP e UDP no IP e portas especificados
    scan_results = nm.scan(target_ip, target_ports, arguments="-sS -sU")

    # Lista com os resultados formatados para serem adicionados ao banco
    formatted_results = {}

    # Para cada alvo no resultado do scan TCP
    for target in scan_results["scan"][target_ip]["tcp"]:
        
        # Converte a porta de string para inteiro
        port = int(target)

        # Obtém o nome do serviço associado à porta
        service = scan_results["scan"][target_ip]["tcp"][target]["name"]

        # Armazena o nome do serviço e o protocolo TCP no dicionário de resultados formatados
        formatted_results[str(port)] = {"service": service, "protocol": "TCP"}

    # Para cada alvo no resultado do scan UDP
    for target in scan_results["scan"][target_ip]["udp"]:
        
        # Converte a porta de string para inteiro
        port = int(target)

        # Obtém o nome do serviço associado à porta
        service = scan_results["scan"][target_ip]["udp"][target]["name"]

        # Armazena o nome do serviço e o protocolo UDP no dicionário de resultados formatados
        formatted_results[str(port)] = {"service": service, "protocol": "UDP"}

    # Retorna os resultados formatados
    return formatted_results

