# Port Scanner


![Scanner](https://github.com/44SEC/pyscan/assets/129625591/46ea0ea6-a17e-4c9d-9bf7-d42d2bcd5cfe.png)

# Badges
![badge1](https://img.shields.io/badge/python-3.11-blue) ![badge2](https://img.shields.io/badge/status-aguardando%20revis%C3%A3o-yellow) ![badge3](https://img.shields.io/badge/gitstars-4-blue) ![badge4](https://img.shields.io/badge/testado%20por-44Sec-green) ![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

# Índice 

* [Título e Imagem de capa](#título-e-imagem-de-capa)
* [Badges](#badges)
* [Índice](#índice)
* [Descrição do Projeto](#descrição-do-projeto)
* [Status do Projeto](#status-do-projeto)
* [Port Scanner](#port-scanner)
* [Topologia](#topologia)
* [Funcionalidades e Demonstração da Aplicação](#funcionalidades-e-demonstração-da-aplicação)
* [Tecnologias utilizadas](#tecnologias-utilizadas)
* [Link de vídeo explicativo](https://)
* [Pessoas Desenvolvedoras do Projeto](#pessoas-desenvolvedoras-do-projeto)
* [Licença](#licença)


# Descrição do Projeto

O seguinte projeto tem como objetivo realizar uma ferramenta usada para verificar quais portas estão abertas em um sistema, seja em uma máquina ou em um servidor. 

# Status do Projeto

O projeto foi desenvolvido diante da proposta de trabalho do professor Fábio Cabrini, como quarto checkoint da disciplina Coding For Security da turma 1TDCG da Faculdade de Adminsitração e Informatica Paulista. Aguardando aprovação do docente responsável.


# O Port Scanner

Um Port Scanner é uma ferramenta ou software projetado para identificar quais portas de comunicação estão abertas em um sistema de computador ou em uma rede. Portas são pontos de extremidade numéricos usados ​​para distinguir diferentes serviços e processos em uma rede.

O objetivo principal de um Port Scanner é mapear as portas abertas em um alvo, permitindo a análise das configurações de segurança e da disponibilidade dos serviços. 

# Topologia

![diagrama drawio](https://github.com/44SEC/pyscan/assets/129625591/3e331648-28ac-4b35-b186-413f51347dd5)

# Funcionalidades e Demonstração da Aplicação

* [Explicando e demonstrando "pyscan.py"](https://youtu.be/SfpW_mEFfuE)

Para executar o programa, inicie primeiro o interpretador com o comando py ou python3, no sistema operacional Linux baseado em Debian.

* Clone o repositório no diretório desejado

```
$ git clone https://github.com/44SEC/pyscan.git
```

* Entre dentro do diretório
```
$ cd pyscan
```

* Crie seu ambiente virtual
```
$ python3 -m venv venv
```

* Ative o seu ambiente virtual
```
$ source venv/bin/activate
```

* Instale as dependencias do projeto
```
$ pip3 install -r requirements.txt
```

* Execute o script com o seguinte comando

```
$ sudo python3 pyscan.py -t <target-ip> -p <range-ports>
```

# Demonstração de execução
![terminal-pyscan](https://github.com/44SEC/pyscan/assets/78339857/9f2f46f3-b400-474f-93e5-4564a15a9d23)

# Demonstração MongoDB
![mongodb-pyscan](https://github.com/44SEC/pyscan/assets/78339857/0338c916-493a-4fde-8a76-46e87d421d60)

# Tecnologias utilizadas

Para realizar o projeto, o grupo 44SEC optou por utilizar a liguagem Python, MongoDB, Nmap em um ambiente Linux

<table>
  <tr>
    <td>Python</td>
    <td>MongoDB</td>
    <td>Nmap</td>
  </tr>
  <tr>
    <td>3.8</td>
    <td>4.5</td>
    <td>0.7</td>
  </tr>
</table>

# Pessoas Desenvolvedoras do Projeto

Felipe de Resende Madeira 

João Victor Santos Alves 

Rakel de Macedo Oliveira 

Pedro Henrique Lima Vieira 

Suellen Guedes Rufino 

# Licença

GNU LICENSE





