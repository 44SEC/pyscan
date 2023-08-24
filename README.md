# PortScanner

Um PortScanner é uma ferramenta usada para verificar quais portas estão abertas em um sistema remoto. É comumente usado para fins de segurança e administração de redes.

## Instalação

1. Repositório `git clone https://github.com/seu-usuario/seu-repositorio.git`
2. Acesse o diretório do projeto: `xxxxxxx`
3. Execute o portscanner: `python portscanner.py`

## Como Usar

Você pode executar o PortScanner com os seguintes argumentos:

- `-t` ou `--target`: Especifica o alvo para escanear (ex: xxx.xxx.x.x).
- `-p` ou `--ports`: Especifica as portas a serem verificadas (ex: `80,443,8080`).

Exemplo de uso:

```sh
python portscanner.py -t xxx.xxx.x.x -p 80,443,8080
