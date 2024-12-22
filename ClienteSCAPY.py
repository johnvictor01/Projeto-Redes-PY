"""
Implementacao do cliente Scapy do projeto final da disciplina de 
Redes de computadores I - GDSCO0062 
Período: 24.1

Discentes:
John Victor De Oliveria Atanazio - 20220125879
Messias da Silva Guedes  - 20220006199

Doscente:
Ewerton Monteiro Salvador

"""

import random, socket
from scapy.all import IP, UDP, Raw, sr1


# Apresentando as respostas formatadas: 
def printResp(raw_payload,TypeReq):
    print("\n=======\n")
    if TypeReq == 1:  # Data e hora
        data_hora = raw_payload[4:].decode('utf-8', errors='ignore')  
        print(f"Data e Hora: {data_hora}")

    elif TypeReq == 2:  # Mensagem motivacional
        mensagem = raw_payload[4:].decode('utf-8', errors='ignore') 
        print(f"Mensagem Motivacional: {mensagem}")

    elif TypeReq == 3:  # Quantidade de respostas
        quantidade_respostas = int.from_bytes(raw_payload[4:], byteorder='big')
        print(f"Quantidade de respostas: {quantidade_respostas}")

    else:
        print("Nenhuma resposta recebida após o tempo limite.")

    print("\n=======\n")
    


def ConseguirIPOrigem():
    try:
        # Criar um socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Conectar a um endereço IP e porta (pode ser qualquer IP externo)
        s.connect(("8.8.8.8", 80))  # 8.8.8.8 é o DNS público do Google
        ip = s.getsockname()[0]  # Obter o endereço IP local
        s.close()  # Fechar o socket
        return ip
    except Exception as e:
        return f"Erro ao obter IP: {e}"
    

def dividirIp(ip):
    octetos = list(map(int, ip.split('.')))
    
    if len(octetos) != 4 or any(octeto < 0 or octeto > 255 for octeto in octetos):
        raise ValueError("IP inválido. Certifique-se de que ele esteja no formato correto.")
    
     # Converto o IP para uma sequencia de 32 bits
    ip_32bits = (octetos[0] << 24) | (octetos[1] << 16) | (octetos[2] << 8) | octetos[3] 
    
    # extraio os 16 bits mais significativos e os 16 bits menos significativos
    BITSMAIsS = (ip_32bits >> 16) & 0xFFFF
    BITSMENOsS = ip_32bits & 0xFFFF

    return BITSMAIsS , BITSMENOsS


def calcularCheksum(udp, ip, req):
    
    #Começo somando os valores do cabeçalho Udp e o protocolo de rede e o tamanho do pseudocabeçalho IP
    somatorio = sum(udp.values()) +ip['ProtoRD'] + ip['Tam']

    #Aqui pegamos os ip's e dividimos eles em partes mais signifivativas e menos significativas
    ipSgnfctvorigem,ipMNsSgnfctvorigem = dividirIp(ip['IPorg'])
    ipSgnfctvdestino,ipMNsSgnfctvdestino =  dividirIp(ip['IPdest'])

    #Consigo os bits mais significativos e menos significativos da requisivos
    req = req << 8
    BITMAIsS = (req >> 16) & 0xFFFF
    BITMENOsS = req & 0xFFFF

    

    #logo apos somo os ip's divididos nas partes mais significativas e menos significativas
    somatorio += ipSgnfctvorigem + ipMNsSgnfctvorigem + ipSgnfctvdestino + ipMNsSgnfctvdestino

    #Logo apos isso somo os bits mais significativos e menos significativos da requisicao no somatorio
    somatorio += BITMAIsS + BITMENOsS

     # enquanto houver overflow (wraparound) - parte mais significativa maior que 0
    while somatorio >> 16:
        # adiciona a parte que transbordou aos 16 bits menos significativos
        somatorio = (somatorio & 0xFFFF) + (somatorio >> 16)

    #aqui faço o complemento de um
    somatorio = ~somatorio & 0xFFFF

    return somatorio



def createReq(TypeReq, idf):
    # associa o tipo da requisicao aos bytes do identificador
    # depois retorna um valor de 32 bits onde os 16 bits mais significativos são o tipo
    # e os 16 bits menos significativos são o identificador
    if TypeReq == 1:
        return (0x00<<16) | idf
    elif TypeReq == 2:
        return (0x01<<16) | idf
    elif TypeReq == 3:
        return (0x02<<16) | idf     
    else:
        print("\nF")
    return -1


def cabecalho(TypeReq):
    # Gero o identificador e a porta de origem e  consigo o 'IPorigem', através da função utilizando sockets
    Iporigem = ConseguirIPOrigem()
    idf = random.randint(1, 65535)
    Port = random.randint(45000, 55000)

    # Cabeçalho udp e pseudoCabeçalhoIp criado como um dicionário para facilitar o acesso as informações
    cabecalhoUDP= {
        'portOrigin' : Port,
        'PortDestin': 50000,
        'Tam' : 11,
        'Cheksum' : 0
    }

    pseudoCabecalhoIP = {
        'IPorg': Iporigem,
        'IPdest': "15.228.191.109",
        'ProtoRD': 17,
        'Tam' : 11
    }

    #Chama a função de criar Requisição 
    Req = createReq(TypeReq, idf)
    if Req == -1:
        print("\nF")

    #calcula o cheksum e atribui o valor no campo cheksum dentro do dicionario 
    cabecalhoUDP ['Cheksum'] = calcularCheksum(cabecalhoUDP,pseudoCabecalhoIP, Req)

    #Trasforma a requisicao para uma requisição em bytes
    ReqBytes = Req.to_bytes(3, byteorder='big')

    #Aqui Cria o pacote Final que sera enviado para o 
    pacoteFinal = IP(dst=pseudoCabecalhoIP['IPdest']) / UDP(sport = cabecalhoUDP['portOrigin'], dport = cabecalhoUDP['PortDestin'],
                                                             len= cabecalhoUDP['Tam'], chksum = cabecalhoUDP['Cheksum'])/Raw(load=ReqBytes)
    
    #aqui eu utilizo a função sr1 e envio o pacote final com um timeout de 3 segundos e depois extraio o payload bruto
    #depois passo o payload para uma função de print, onde sera tratado de acordo com o tipo da mensagem
    resposta = sr1(pacoteFinal, timeout= 3)
    raw_payload = resposta[UDP].payload.load
    printResp(raw_payload, TypeReq)





def main():
    while True:
        print("Digite uma opção:")
        print("1. Data e hora atual")
        print("2. Uma mensagem motivacional para o fim do semestre")
        print("3. A quantidade de respostas emitidas pelo servidor até o momento")
        print("4. Sair")
        print("---> ", end='')

        try:
            TypeReq = int(input())
        except ValueError:
            print("\nPor favor, digite um valor válido.")
            continue

        if TypeReq in [1, 2, 3]:
            cabecalho(TypeReq)  
        elif TypeReq == 4:
            print("\nSaindo...")
            break
        else:
            print("\nDigite um valor válido!")

main()