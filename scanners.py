import nmap


# Função que lê o arquivo services e cria um dicionário com os serviços
def Read_Services_Local():

    # Dict que contém os serviços rodando na máquina
    services_dict = {}

    # Abrindo e lendo o /etc/services para ver o nome dos serviços rodando
    with open('/etc/services', 'r') as f:
        
        # Lê linha a linha e armazena
        lines = f.readlines()

        # Para cada linha em linhas
        for line in lines:
            
            # Verifica se a linha não começa com '#', indicando um comentário
            if not line.startswith('#'):
                
                # Divide a linha em partes separadas por espaços
                parts = line.split() 
                
                # Verifica se há pelo menos duas partes na linha
                if len(parts) >= 2:  

                    # O primeiro elemento é o nome do serviço
                    service_name = parts[0] 
                    
                    # O segundo elemento é o número da porta e protocolo
                    port_protocol = parts[1] 

                    # Divide a porta e protocolo separados por '/'
                    port, protocol = port_protocol.split('/')

                    # Adiciona a porta e o nome do serviço ao dicionário
                    services_dict[port] = service_name

    # Retorna o dicionário com a porta e o nome do serviço
    return services_dict 


# Função para realizar o scan de portas TCP
def Port_Scan_TCP(target_ip, target_ports):

    # Cria uma instância do scanner de portas Nmap
    nm = nmap.PortScanner()

    # Realiza o scan de portas TCP no IP e portas especificados
    scan_results = nm.scan(target_ip, target_ports, arguments="-sS")

    # Lê o arquivo services para obter os serviços correspondentes
    services_dict = Read_Services_Local()

    # Lista com os resultados formatados para serem adicionados ao banco
    formatted_results_tcp = {}

    # Verifica se há resultados para a porta TCP
    if target_ip in scan_results["scan"]:

        tcp_ports = scan_results["scan"][target_ip].get("tcp", {})

        for target, result in tcp_ports.items():

            # Converte a porta de string para inteiro
            port = int(target)

            # Verifica se a porta está aberta
            is_open = result["state"] == "open"

            if is_open:

                # Obtém o nome do serviço associado à porta
                service = services_dict.get(str(port), "Desconhecido")

                # Define o status da porta (aberta/fechada)
                port_status = "open" if is_open else "closed"

                # Armazena o nome do serviço, o protocolo TCP e o status no dicionário de resultados formatados
                formatted_results_tcp[str(port)] = {"service": service, "status": port_status}

    else:
        print(f"Nenhuma porta TCP aberta encontrada para o IP {target_ip}.")

    # Imprime os dados das portas abertas
    print("\n[*] Protocolo TCP | Portas Abertas e seus Serviços:")
    for port, data in formatted_results_tcp.items():
        print(f"[!] Porta: {port}, Serviço: {data['service']}, Protocolo: TCP")

    # Retorna os resultados formatados
    return formatted_results_tcp


# Função para realizar o scan de portas UDP
def Port_Scan_UDP(target_ip, target_ports):

    # Cria uma instância do scanner de portas Nmap
    nm = nmap.PortScanner()

    # Realiza o scan de portas UDP no IP e portas especificados
    scan_results = nm.scan(target_ip, target_ports, arguments="-sU")

    # Lê o arquivo services para obter os serviços correspondentes
    services_dict = Read_Services_Local()

    # Lista com os resultados formatados para serem adicionados ao banco
    formatted_results_udp = {}

    # Verifica se há resultados para a porta UDP
    if target_ip in scan_results["scan"]:

        udp_ports = scan_results["scan"][target_ip].get("udp", {})

        for target, result in udp_ports.items():

            # Converte a porta de string para inteiro
            port = int(target)

            # Verifica se a porta está aberta
            is_open = result["state"] == "open"

            if is_open:
                # Obtém o nome do serviço associado à porta
                service = services_dict.get(str(port), "Desconhecido")

                # Define o status da porta (aberta/fechada)
                port_status = "open" if is_open else "closed"

                # Armazena o nome do serviço, o protocolo UDP e o status no dicionário de resultados formatados
                formatted_results_udp[str(port)] = {"service": service, "status": port_status}

    else:
        print(f"Nenhuma porta UDP aberta encontrada para o IP {target_ip}.")

    # Imprime dados das portas abertas
    print("\n[*] Protocolo UDP | Portas Abertas e seus Serviços:")
    for port, data in formatted_results_udp.items():
        print(f"[!] Porta: {port}, Serviço: {data['service']}, Protocolo: UDP")

    # Retorna os resultados formatados
    return formatted_results_udp

