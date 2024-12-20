# Projeto de Redes - 2024.1
# Discentes:
# Carlos Rafael Torres Miranda Novack, 20210066961
# Avani Maria de Fonseca, 20210067000

import socket
import random
import struct
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from scapy.sendrecv import sniff

# Endereço IP e porta do servidor
SERVER_IP = '15.228.191.109'
SERVER_PORT = 50000
CLIENT_PORT = random.randint(1024, 65535) # Gera uma porta aleatória para o cliente

# Função que solicita ao usuário a escolha de um dos 4 tipos de requisição 
def get_escolha_usuario():
    print('\nSelecione o que deseja requisitar:')
    print('1 - Data e hora atual')
    print('2 - Uma mensagem motivacional para o fim do semestre')
    print('3 - A quantidade de respostas emitidas pelo servidor até o momento')
    print('4 - Sair')
    escolha_usuario = input('Insira sua escolha: ')
    
    if  escolha_usuario == '1':
        return 0x00
    elif escolha_usuario == '2':
        return 0x01
    elif escolha_usuario == '3':
        return 0x02
    elif escolha_usuario == '4':
        return None
    else:
        print('Escolha inválida. Por favor, tente novamente')
        return get_escolha_usuario()

# Função que constrói a mensagem de requisição
def build_msg(tipo_req):
    identificador = random.randint(1, 65535)
    message = struct.pack('!BH', tipo_req, identificador)
    return message, identificador

# Função para processar a resposta do servidor no cliente UDP
def proc_resposta_udp(data):
    # Desempacota os dados da resposta recebida
    req_res, identificador, tamanho_resposta = struct.unpack('!BHB', data[:4])

    # Se o cliente solicitou a quantidade de respostas emitidas pelo servidor até o momento
    if req_res == 0x12:
        resposta = struct.unpack('!I', data[4:8])[0] # Desempacota a resposta como um inteiro
    else: 
        resposta = data[4:].decode('utf-8')

    return req_res, identificador, tamanho_resposta, resposta

# Função para processar a resposta do servidor no cliente SCAPY
def proc_resposta_scapy(data):
    if data and UDP in data: # Verifica se o pacote tem camada UDP
        payload = bytes(data[UDP].payload) # Converte o pacote Scapy em bytes
        req_res, identificador, tamanho_resposta = struct.unpack('!BHB', payload[:4]) 

        # Se o cliente solicitou a quantidade de respostas emitidas pelo servidor até o momento
        if req_res == 0x12:
            resposta = struct.unpack('!I', data.load[4:8])[0] # Desempacota a resposta como um inteiro
        else: 
            resposta = data.load[4:].decode('utf-8')

        return req_res, identificador, tamanho_resposta, resposta
    else:
        print("Pacote recebido não contém dados UDP válidos.")
        return None, None, None, None
        

# Função que implementa o cliente UDP
def cliente_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Cria um socket UDP
    
    while True:
        tipo_req = get_escolha_usuario() # Obtém a escolha do usuário
        if tipo_req is None:
            print('Saindo...')
            break

        # Constrói e envia a requisição
        msg, identificador = build_msg(tipo_req)
        sock.sendto(msg, (SERVER_IP, SERVER_PORT))
        
        # Recebe a resposta do servidor
        data, _ = sock.recvfrom(1024)
        req_res, identificador, tamanho_resposta, resposta = proc_resposta_udp(data)
        
        # Exibe a resposta recebida
        print(f'\nTipo da resposta (em hexadecimal): {hex(req_res)}')
        print(f'ID: {identificador}')
        print(f'Tamanho da resposta do servidor: {tamanho_resposta}')
        print(f'Resposta do servidor: {resposta}')

    sock.close() # Fecha o socket após o uso

# Função que implementa o cliente SCAPY
def cliente_scapy():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Cria um socket UDP
    
    while True:
        tipo_req = get_escolha_usuario() # Obtém a escolha do usuário
        if tipo_req is None:
            print('Saindo...')
            break

        # Constrói e envia a requisição
        msg, identificador = build_msg(tipo_req)
        sock.sendto(msg, (SERVER_IP, SERVER_PORT))
        
        # Constrói o UDP e o IP
        pacote = UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        pacote = IP(dst=SERVER_IP) / pacote

        # Calcula o checksum e define no pacote
        pacote[UDP].chksum = checksum_scapy(pacote)

        # Limpa os pacotes pendentes no buffer de recebimento para garantir que o cliente vai sempre receber a mensagem com a informação desejada
        sniff(count=0, timeout=0.1)

        # Recebe a resposta do servidor
        data = sr1(pacote, timeout=2) # Envia o pacote e aguarda resposta

        if data:
            req_res, identificador, tamanho_resposta, resposta = proc_resposta_scapy(data)
            # Exibe a resposta recebida
            print(f'\nTipo da resposta (em hexadecimal): {hex(req_res)}')
            print(f'ID: {identificador}')
            print(f'Tamanho da resposta do servidor: {tamanho_resposta}')
            print(f'Resposta do servidor: {resposta}')

    sock.close() # Fecha o socket após o uso

# Função para calcular o checksum para o SCAPY
def checksum_scapy(data):
    # Verifica se o pacote possui as camadas IP e UDP
    if IP in data and UDP in data:
        pac_udp = bytes(data[UDP]) # Armazena o pacote UDP
        pac_ip = bytes(data[IP]) # Armazena o pacote IP
        pseudo_cab = struct.pack('!4s4sBBH', 
                                    pac_ip[12:16],  # Endereço de origem
                                    pac_ip[16:20],  # Endereço de destino
                                    0,              # Preenchido com 0
                                    17,             # Protocolo UDP (17)
                                    len(pac_udp))   # Comprimento do UDP
        
        checksum_data = pseudo_cab + pac_udp # Combina cabeçalho pseudo com pacote UDP
        
        # Realiza o cálculo do checksum
        if len(checksum_data) % 2 != 0:  # Se o comprimento for ímpar, adiciona um byte nulo
            checksum_data += b'\x00'
        
        checagem = sum(struct.unpack('!%dH' % (len(checksum_data) // 2), checksum_data))
        checagem = (checagem & 0xFFFF) + (checagem >> 16)  # Adiciona os carry
        checagem = ~checagem & 0xFFFF  # Inverte os bits para fazer o complemento de 1
        return checagem

# Main para o usuario escolher entre UPD e SCAPY
if __name__ == "__main__":
    print('Qual cliente deseja utilzar')
    print('1 - Socket UDP')
    print('2 - Biblioteca SCAPY')
    escolha_main = input('Insira sua escolha: ')
    
    if escolha_main == '1':
        cliente_udp()
    elif escolha_main == '2':
        cliente_scapy()
    else:
        print('Escolha invalida, encerrando o progerama...')
    