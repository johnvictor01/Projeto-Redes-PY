"""
Implementacao do cliente Utilizando Socket's do projeto final da disciplina de 
Redes de computadores I - GDSCO0062 
Período: 24.1

Discentes:
John Victor De Oliveria Atanazio - 20220125879
Messias da Silva Guedes  - 20220006199

Doscente:
Ewerton Monteiro Salvador

"""
import socket, random, struct

# Configurações do servidor
SERVER_IP = '15.228.191.109'  
SERVER_PORT = 50000           
ADDRESS = (SERVER_IP, SERVER_PORT)  # Combinação do IP e porta

# Função para criar a mensagem de requisição
def create_request(TypeReq):
    req_res = 0x00  # Indica que é uma requisição
    request_type = TypeReq & 0x0F  # Obtém o tipo da requisição
    identifier = random.randint(1, 65535)  

    # Monta a mensagem de requisição
    request = (req_res << 4) | request_type
    message = struct.pack('!BH', request, identifier)  # Empacota a mensagem em bytes
    
    return message, identifier  # Retorna a mensagem e o identificador

# Função para enviar a requisição e receber a resposta
def send_request(sock, TypeReq):
    request, identifier = create_request(TypeReq)  # Cria a requisição
    sock.sendto(request, ADDRESS)  # Envia a requisição

    # Recebe a resposta do servidor
    response, _ = sock.recvfrom(1024)
    return response, identifier  

# Função para interpretar a resposta recebida
def parse_response(response):
    # Desempacota a resposta
    header = struct.unpack('!B H B', response[:4])
    req_res = (header[0] >> 4) & 0x0F  # Campo de requisição/resposta
    res_type = header[0] & 0x0F  # Tipo da resposta
    identifier = header[1]  # Identificador
    size = header[2]  # Tamanho da carga útil

    # Processa a resposta com base no tipo
    print("\n=======\n")
    if res_type == 0:
        print("Data e hora:", response[4:4 + size].decode())
    elif res_type == 1:
        print("Mensagem motivacional:", response[4:4 + size].decode())
    elif res_type == 2:
        count = struct.unpack('!I', response[4:4 + size])[0]
        print(f"Quantidade de respostas enviadas: {count}")
    elif res_type == 3:
        print("Requisição inválida.")

    print("\n=======\n")
# Função principal do cliente
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Cria o socket UDP
    
    while True:
       
        print("Digite uma opção:")
        print("1. Data e hora atual")
        print("2. Uma mensagem motivacional para o fim do semestre")
        print("3. A quantidade de respostas emitidas pelo servidor até o momento")
        print("4. Sair")
        print("---> ", end='')
        
        op = int(input("\nDigite sua escolha: "))
        
        if op == 4:
            print("Saindo...")
            break

        # Mapeia a opção para o tipo de requisição
        TypeReq = op - 1
        
        try:
            response, identifier = send_request(sock, TypeReq)  # Envia a requisição
            parse_response(response)  # Interpreta a resposta
        except Exception as e:
            print(f"Erro na comunicação: {e}")
    
    sock.close()  # Fecha o socket

main()  

