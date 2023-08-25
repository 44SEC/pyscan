from pymongo import MongoClient


# Função que insere os dados no MongoDB
def Insert_MongoDB(data):

    # Cria uma conexão com o servidor MongoDB local
    client = MongoClient("mongodb://localhost:27017/")
    
    # Acessa o banco de dados "port_scans"
    db = client["port_scans"]

    # Acessa a coleção "scan_results" dentro do banco de dados
    collection = db["scan_results"]

    # Insere os dados no MongoDB
    collection.insert_one(data)

    # Fecha a conexão com o MongoDB
    client.close()


# Função que pega os dados do MongoDB
# def Get_