# 4 - Implemente um sistema que receba pela linha de comando o caminho de 2 arquivos:
# uma chave pública e um arquivo de texto contendo uma assinatura digital. Seu sistema
# deve validar a assinatura digital contida no arquivo, informando para o usuário se a
# assinatura é válida ou não.

import rsa
import os
import re

def getFiles(dirr):
    print(dirr)
    print("ATENÇÃO: OS PATHS PODEM CONTER ASPAS SIMPLES, MAS DEVEM TER BARRAS E NÃO TER ESPAÇOS")
    print("Esse é seu path atual, caso deseje usar ele para selecionar os arquivos, digite 1." +
          " Obs: você só poderá entrar em pastas filhas desse diretório." +
          " Digite qualquer outro valor para continuar")
    continuar = input("\nDIGITE OU INFORME O PATH PRINCIPAL: ") != "1"
    publicKeyPath = ""
    txtFilePath = ""

    if (continuar):
        print("")
        publicKeyPath = input(
            "Digite o path onde a ___CHAVE PÚBLICA___, para descriptografar, está localizada: ")
        publicKeyPath = publicKeyPath.strip()
        publicKeyPath = re.sub('\'', '', publicKeyPath)
        print("")
        txtFilePath = input(
            "Digite o path onde o ___ARQUIVO DE TEXTO ASSINADO___ está: ")
        txtFilePath = txtFilePath.strip()
        txtFilePath = re.sub('\'', '', txtFilePath)
    else:
        previousDirr = dirr
        while(os.path.isdir(dirr)):
            print("")
            print(os.listdir(dirr))
            valor = input(
                "Isso que existe na pasta local, digite o nome do arquivo que você deseja usar como publicKey ou da pasta que você deseja entrar: ")
            dirr = os.path.join(dirr, valor)

        if (os.path.exists(dirr)):
            print("")
            print(f'OK!!! {dirr}')
            publicKeyPath = dirr
        else:
            print("Arquivo invalido, tente novamente")
            exit()

        dirr = previousDirr
        while(os.path.isdir(dirr)):
            print("")
            print(os.listdir(dirr))
            valor = input(
                "Isso que existe na pasta local, digite o nome do arquivo que você deseja usar como txtFile assinado ou da pasta que você deseja entrar: ")
            dirr = os.path.join(dirr, valor)

        if (os.path.exists(dirr)):
            print("")
            print(f'OK!!! {dirr}')
            txtFilePath = dirr
        else:
            print("")
            print("Arquivo invalido, tente novamente")
            exit()

    return publicKeyPath, txtFilePath

def getPublicKey(publicKeyPath):
    with open(publicKeyPath, "r") as pk:
        try:
            return rsa.PublicKey.load_pkcs1(pk.read())
        except Exception as e:
            print(f'Erro ao pegar a chave publica:{e.__class__.__name__, e}')
            exit()

def validadeSignature(txtFilePath, publicKey):
    # print(txtFilePath)

    # PEGA O HEX, VAI ATE -256
    # CONVERTE PARA BYTES, ISSO VAI SER O TEXTO (EM BYTES)
    # SUBSTITUI O TEXTO NO BYTES, O QUE SOBRAR VAI SER A ASSINATURA (EM BYTES)

    with open(txtFilePath, "rb") as txtFile:
        # posso converter para hex e pesquisar no content hex para substituir
        contentBytes = txtFile.read()
        # tenho que usar o bytes ou normal no verify
        txtFile.seek(0, os.SEEK_SET)
        contentHex = txtFile.read().hex()

    # IDENTIFICA O QUE EH TEXTO
    txt = bytes.fromhex(contentHex[0:-256])
    # print(txt)

    # REMOVE O TXT
    signature = contentBytes.replace(txt, b'')
    # print(signature)

    # REMOVE O \n
    txt = txt[0:-1]

    # newContent = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis commodo scelerisque lorem dignissim faucibus. Sed feugiat mi id sem convallis iaculis. Nulla non dictum nulla, eu commodo nisi. Cras mattis, purus a varius sollicitudin, nulla lectus tempor sit.'
    # # print(txt.__eq__(newContent))

    # newSignature = b'~\xc9\xbb\xee\xfa\x7f\x1b9|\xd8\xf5H\xcf<\x1b\x94\x93u\xe2\x1b74\xcf\xd9\xa4\xee\x06I\'\x18\xcc(\xe2\t\xaaE>\xbc_m\xbd\xcf,\xca\x84\xeb\xa2v_\x13\xa6\x08$\x1c\x02\xd1\x03z\xb2L\x98*`\x0c\xeb\'\xce\xce\x18\x8f\x96\xa2\r$R-\t\xb3\xde\x16\xa6Oh\rt\xc4j\x99$\xc0\x9b\x07\xe5P\xce\xa4\xd6 \xbf\xb6\x8eS\x102E\xe0y\x8a<d\xea.\xa8\xd2<\x82\xc3B\xca5\xe7R\xcbI\xb9H@\x02'
    # # print(signature == newSignature)

    # print(rsa.verify(newContent,
    #                  newSignature, publicKey))

    if (len(txt) != 0):
        try:
            print(
                f' - - > Verificado! HASH usado: {rsa.verify(txt,signature, publicKey)} :)')
        except Exception as e:
            print(f"Erro de verificação: {e.__class__.__name__, e}!")
            exit()
    else:
        print("Texto está vazio")


if __name__ == "__main__":
    dirr = os.path.dirname(os.path.abspath(__file__))

    print("")
    publicKeyPath, txtFilePath = getFiles(dirr)

    # publicKeyPath, txtFilePath = ("/Users/rafael/Documents/segurancao-vp2/keysPartA/publicKey.pem",
    #                               "/Users/rafael/Documents/segurancao-vp2/teste_assinado.txt")

    print("Perfeito... Pegando chave publica...")

    publicKey = getPublicKey(publicKeyPath)

    print("Perfeito... Validando assinatura...\n")
    signature = validadeSignature(txtFilePath, publicKey)
