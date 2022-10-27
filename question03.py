# 3 - Implemente um sistema que receba pela linha de comando o caminho de 2 arquivos:
# uma chave privada e um arquivo de texto. Seu sistema deve gerar uma assinatura digital
# para o arquivo, tendo como resultado um novo arquivo assinado. Esse arquivo deve ser
# armazenado no mesmo diretório do arquivo original, com nome terminando em "_assinado".

import rsa
import os
import shutil
import re

def getFiles(dirr):
    print(dirr)
    print("ATENÇÃO: OS PATHS PODEM CONTER ASPAS SIMPLES, MAS DEVEM TER BARRAS E NÃO TER ESPAÇOS")
    print("Esse é seu path atual, caso deseje usar ele para selecionar os arquivos, digite 1." +
          " Obs: você só poderá entrar em pastas filhas desse diretório." +
          " Digite qualquer outro valor para continuar")
    continuar = input("\nDIGITE OU INFORME O PATH PRINCIPAL: ") != "1"
    privateKeyPath = ""
    txtFilePath = ""

    if (continuar):
        print("")
        privateKeyPath = input(
            "Digite o path onde a ____CHAVE PRIVADA___, para assinatura, está localizada: ")
        privateKeyPath = privateKeyPath.strip()
        privateKeyPath = re.sub('\'', '', privateKeyPath)
        print("")
        txtFilePath = input(
            "Digite o path onde o ____ARQUIVO DE TEXTO___ está: ")
        txtFilePath = txtFilePath.strip()
        txtFilePath = re.sub('\'', '', txtFilePath)
    else:
        previousDirr = dirr
        while(os.path.isdir(dirr)):
            print("")
            print(os.listdir(dirr))
            valor = input(
                "Isso que existe na pasta local, digite o nome do arquivo que você deseja usar como privateKey ou da pasta que você deseja entrar: ")
            dirr = os.path.join(dirr, valor)

        if (os.path.exists(dirr)):
            print("")
            print(f'OK!!! {dirr}')
            privateKeyPath = dirr
        else:
            print("Arquivo invalido, tente novamente")
            exit()

        dirr = previousDirr
        while(os.path.isdir(dirr)):
            print("")
            print(os.listdir(dirr))
            valor = input(
                "Isso que existe na pasta local, digite o nome do arquivo que você deseja usar como txtFile ou da pasta que você deseja entrar: ")
            dirr = os.path.join(dirr, valor)

        if (os.path.exists(dirr)):
            print("")
            print(f'OK!!! {dirr}')
            txtFilePath = dirr
        else:
            print("")
            print("Arquivo invalido, tente novamente")
            exit()

        dirr = previousDirr
        while(os.path.isdir(dirr)):
            print(os.listdir(dirr))
            valor = input(
                "Isso que existe na pasta local, digite o nome do arquivo que você deseja usar como publicKey ou da pasta que você deseja entrar: ")
            dirr = os.path.join(dirr, valor)

        if (os.path.exists(dirr)):
            print(f'OK!!! {dirr}')
        else:
            print("Arquivo invalido, tente novamente")
            exit()

    return privateKeyPath, txtFilePath

def getPrivateKey(privateKeyPath):
    with open(privateKeyPath, "r") as pk:
        try:
            return rsa.PrivateKey.load_pkcs1(pk.read())
        except Exception as e:
            print(f'Erro ao pegar a chave privada:{e.__class__.__name__, e}')
            exit()

def processing(txtFilePath, privateKey):
    print("Perfeito... Gerando assinatura...")
    signature = generateSignature(txtFilePath, privateKey)

    print("Perfeito... Gerando novo arquivo...")
    copyFileAndSign(txtFilePath, signature)

def generateSignature(txtFilePath, privateKey):
    contentB = ""
    # A assinatura gerada, para uma key gerada com n de 1024 bits, terá 256 caracteres

    with open(txtFilePath, "r") as file:
        contentB = file.read()
        print(contentB)

    if (len(contentB) != 0):
        try:
            signature = rsa.sign(contentB.encode(
                "utf-8"), privateKey, 'SHA-384')
            # print(f'Signature (HASH): {signature.hex()} \n')
            print("assinatura feita")
            print(signature)
            return signature
        except Exception as e:
            print(f"Erro de verificação: {e.__class__.__name__, e}")
            exit()
    else:
        return False

def copyFileAndSign(filePath, signature):
    withoutSlashes = filePath.split('/')
    fileName = ""
    filePath = ""
    fileExtension = ""
    for i in range(0, len(withoutSlashes)):
        if i == len(withoutSlashes) - 1:
            fileName = withoutSlashes[i]
            withoutDots = fileName.split('.')
            fileName = withoutDots[0]
            fileExtension = withoutDots[1]
        else:
            filePath = filePath + withoutSlashes[i] + '/'

    filePath = filePath[:-1]
    filePathNoExtension = filePath + '/' + fileName
    fullPath = filePath + '/' + fileName + "." + fileExtension
    newFile = filePathNoExtension + '_assinado' + '.' + fileExtension

    shutil.copyfile(fullPath, newFile)

    print("arquivo para assinatura criado")
    print("Perfeito... Assinando...\n")

    editFile(newFile, signature)

def editFile(newFilePath, signature):
    with open(newFilePath, "rb+") as file:
        file.seek(0, os.SEEK_END)
        file.write(b"\n")
        file.write(signature)
        # print(signature)

    print(" - - > Arquivo para assinatura assinado :)")


if __name__ == "__main__":
    dirr = os.path.dirname(os.path.abspath(__file__))

    print("")
    privateKeyPath, txtFilePath = getFiles(dirr)

    # privateKeyPath, txtFilePath = ("/Users/rafael/Documents/segurancao-vp2/keysPartA/privateKey.pem",
    #                                "/Users/rafael/Documents/segurancao-vp2/teste.txt")

    print("Perfeito... Pegando chave privada...")
    with open(privateKeyPath, "r") as o:
        content = o.read()
    privateKey = getPrivateKey(privateKeyPath)

    processing(txtFilePath, privateKey)


# print(f'txt:{txtFilePath}')
#     with open(txtFilePath, "r") as k:
#         count = 0
#         for line in k.readlines():
#             count += 1
#         print(count)

#  with open(txtFilePath, "rb+") as bFile:
#         print(bFile.read())
#         bFile.seek(0, os.SEEK_SET)
#         bFile.seek(bFile.tell() - 11, os.SEEK_END)
#         content = bFile.read()
#         print(content)
