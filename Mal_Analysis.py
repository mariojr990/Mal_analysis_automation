#Insira sua API key na variavel virus_total_key
virus_total_key = ""
hash = "8b92c23b29422131acc150fa1ebac67e1b0b0f8cfc1b727805b842a88de447de"

import tkinter as tk
from tkinter import filedialog
import hashlib
import requests

def exibir_menu():
    print("===== Menu Principal =====")
    print("1. Full Report Virus Total.")
    print("2. Opção 2")
    print("3. Opção 3")
    print("4. Sair")

def opcao1():
    print("Você escolheu a Opção 1 :Report full VT")
    resultadovt = check_virustotal()
    print(resultadovt)


def opcao2():
    print("Você escolheu a Opção 2: hash do arquivo")
    #obter_hash_md5()
    
def opcao3():
    print("Você escolheu a Opção 3")

def check_virustotal():
    url = f"https://www.virustotal.com/api/v3/files/{hash}"

    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_key
    }

    response = requests.get(url, headers=headers)

    return response.json()

def obter_hash_md5():
    def calcular_md5(arquivo):
        md5 = hashlib.md5()
        with open(arquivo, 'rb') as f:
            while True:
                dados = f.read(4096)
                if not dados:
                    break
                md5.update(dados)
        return md5.hexdigest()

    def escolher_arquivo():
        root = tk.Tk()
        root.withdraw() # Não exibe a janela principal

        arquivo = filedialog.askopenfilename(filetypes=[("Arquivos", "*.*")])

        if arquivo:
            md5 = calcular_md5(arquivo)
            return md5
        else:
            print("Nenhum arquivo selecionado.")
            return None

    hash_md5 = escolher_arquivo()

    if hash_md5:
        print(f"A hash MD5 do arquivo é: {hash_md5}")
    else:
        print("Operação cancelada ou nenhum arquivo selecionado.")

if __name__ == "__main__":
    obter_hash_md5()



# Loop do menu
while True:
    exibir_menu()
    
    escolha = input("Digite o número da sua escolha: ")

    if escolha == '1':
        opcao1()
    elif escolha == '2':
        opcao2()
    elif escolha == '3':
        opcao3()
    elif escolha == '4':
        print("Saindo...")
        break
    else:
        print("Opção inválida. Por favor, escolha novamente.")
