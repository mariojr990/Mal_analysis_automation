from decouple import config
from tkinter import filedialog
import tkinter as tk
import hashlib
import requests
import sys


virus_total_key = config('VIRUSTOTAL_API_KEY')
hash = "8b92c23b29422131acc150fa1ebac67e1b0b0f8cfc1b727805b842a88de447de"

# ----- Opções do Menu -----
def opcao1():
    print("Você escolheu a Opção 1: Report full VT\n")
    check_virustotal()
    


def opcao2():
    print("Você escolheu a Opção 2: Gerar hash do arquivo\n")
    obter_hash_md5()
    
def opcao3():
    print("Você escolheu a Opção 3: Inserir hash de arquivo\n")
# --------------------------

def sair():
    root.destroy()
    sys.exit()

# Função para realizar a pesquisa na VirusTotal conforme Hash passada
def check_virustotal():
    url = f"https://www.virustotal.com/api/v3/files/{hash}"

    headers = {
        "accept": "application/json",
        "x-apikey": virus_total_key
    }

    response = requests.get(url, headers=headers)
    # response.json()
    arquivo_data = response.json()
    # print(arquivo_data)

    sandbox_verdicts = arquivo_data['data']['attributes']['sandbox_verdicts']

    for sandbox, verdict in sandbox_verdicts.items():
        print(f"Sandbox: {sandbox}")
        print(f"Category: {verdict.get('category', 'N/A')}")
        print(f"Confidence: {verdict.get('confidence', 'N/A')}")
        print(f"Sandbox Name: {verdict.get('sandbox_name', 'N/A')}")
        print(f"Malware Classification: {verdict.get('malware_classification', 'N/A')}")
        print("\n")



# Função para Obter hash de um arquivo selecionado
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
    
    # Titulo da Janela
    root = tk.Tk()
    root.title("Verifica arquiva VirusTotal")
    
    # Titulo dentro da tela
    txt_orientacao = tk.Label(root, text="     ===== Menu Principal =====     ")
    txt_orientacao.pack()

    espaco = tk.Label(root, text="")
    espaco.pack()

    # Criando o menu com três botões
    menu_frame = tk.Frame(root)
    menu_frame.pack()

    button_width = 20

    button1 = tk.Button(menu_frame, text="Full Report Virus Total", command=opcao1, width=button_width, pady=5)
    button1.pack(side=tk.TOP, anchor='w')

    button2 = tk.Button(menu_frame, text="Gerar Hash do Arquivo", command=opcao2, width=button_width, pady=5)
    button2.pack(side=tk.TOP, anchor='w')

    button3 = tk.Button(menu_frame, text="Inserir Hash de Arquivo", command=opcao3, width=button_width, pady=5)
    button3.pack(side=tk.TOP, anchor='w')
    
    espaco = tk.Frame(menu_frame, height=10)
    espaco.pack(side=tk.TOP)

    button_sair = tk.Button(menu_frame, text="Sair", command=sair, fg="red")
    button_sair.pack(side=tk.TOP, anchor='w')

    root.mainloop()



# Loop do menu
    # while True:
    #     exibir_menu()
        
    #     escolha = input("Digite o número da sua escolha: ")

    #     if escolha == '1':
    #         opcao1()
    #     elif escolha == '2':
    #         opcao2()
    #     elif escolha == '3':
    #         opcao3()
    #     elif escolha == '4':
    #         print("Saindo...")
    #         break
    #     else:
    #         print("Opção inválida. Por favor, escolha novamente.")
