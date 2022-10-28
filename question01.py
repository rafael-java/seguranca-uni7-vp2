# 1 - Implemente um sistema que simula uma troca de mensagens entre duas partes cifradas
# através do RSA. Não é necessário pedir o input do usuário, bastando que o sistema exercite
# a geração de pares de chaves públicas e privadas aleatórias, seguido da cifragem e decifragem
# de mensagens de forma correta.

import rsa
import os
import errno

# Geração de pares de chaves públicas e privadas aleatórias
def generatePairOfKeys(parentDir, bits):
    # 2048 é a quantidade de bits que N vai usar
    # (https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/#:~:text=The%20recommended%20RSA%20modulus%20size,2048%20bits%20to%204096%20bits).
    # No PDF do NIST (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf), pag. 54
    # relaciona o tamanho do N com a força de segurança. 2048 é a força equivalente a 112.
    # De acordo com a pagina 59, essa quantidade de força pode ser usada até 2030.
    # Curiosidade: para quebrar essa segurança, em um PC clássico, levaria 300 trilhões de anos.

    (publicKeyA, privateKeyA) = rsa.newkeys(bits)
    (publicKeyB, privateKeyB) = rsa.newkeys(bits)
    try:
        dirc = "keysPartA"
        newDir = os.path.join(parentDir, dirc)
        os.mkdir(newDir)
        dirc = "keysPartB"
        newDir = os.path.join(parentDir, dirc)
        os.mkdir(newDir)
    except OSError as error:
        if not error.errno == errno.EEXIST:
            print(error)
            exit()

    # Poderia ser do tipo PEM (Privacy Enhanced Mail) ou DER,
    # Os arquivos DER são mais comumente vistos em contextos Java.
    # O DER é um certificado encodado, enquanto o PEM é o DER convertido para base64, com headers.

    # ParteA
    with open('keysPartA/publicKey.pem', 'wb') as pk:
        pk.write(publicKeyA.save_pkcs1('PEM'))
    with open('keysPartA/publicKey.pem', 'rb') as pk:
        publicKeyA = rsa.PublicKey.load_pkcs1(pk.read())
    with open('keysPartA/privateKey.pem', 'wb') as pk:
        pk.write(privateKeyA.save_pkcs1('PEM'))
    with open('keysPartA/privateKey.pem', 'rb') as pk:
        privateKeyA = rsa.PrivateKey.load_pkcs1(pk.read())

    # ParteB
    with open('keysPartB/publicKey.pem', 'wb') as pk:
        pk.write(publicKeyB.save_pkcs1('PEM'))
    with open('keysPartB/publicKey.pem', 'rb') as pk:
        publicKeyB = rsa.PublicKey.load_pkcs1(pk.read())
    with open('keysPartB/privateKey.pem', 'wb') as pk:
        pk.write(privateKeyB.save_pkcs1('PEM'))
    with open('keysPartB/privateKey.pem', 'rb') as pk:
        privateKeyB = rsa.PrivateKey.load_pkcs1(pk.read())

    # Retorna em bytes
    return publicKeyA, publicKeyB, privateKeyA, privateKeyB

# Cifragem de mensagem
def encryptMessage(message, key):
    # O tamanho da mensagem deve ser de, no máximo, k-11 bytes (128-11 bytes ou 256-11 bytes).
    # (Message must be a byte string no longer than ``k - 11`` bytes,
    # where ``k`` is the number of bytes needed to encode
    # the ``n`` component of the public key).

    return rsa.encrypt(message.encode('utf-8'), key)

# Decifragem de mensagem
def decryptMessage(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('utf-8')
    except Exception as e:
        print(f"Erro de verificação: {e}")
        exit()


if __name__ == "__main__":
    parentDir = os.path.dirname(os.path.abspath(__file__))
    bits = 1024  # 1024 é mais rápido, mas 2048 é o ideal. Ler explicação no método abaixo
    publicKeyA, publicKeyB, privateKeyA, privateKeyB = generatePairOfKeys(
        parentDir, bits)

    # # #
    print(" ")

    print("Olá parte A...")
    message = "Olá"
    if (len(message) <= (bits / 8) - 11):
        print(f'Enviando mensagem: {message}...')
        print("Para: PARTE B")
    else:
        print("Mensagem muito grande...")

    # Cifragem usando RSA pode ser feita apenas com a public key (e assinatura apenas com private key)
    # de acordo com o padrão RSA (https://www.rfc-editor.org/rfc/rfc3447)
    ciphertext = encryptMessage(message, publicKeyB)

    # # #
    print(" ")

    print("Olá, parte B, você recebeu uma mensagem...")
    print("De: PARTE A")
    print(ciphertext)
    print("\nDescriptografando a mensagem...")

    msg = decryptMessage(ciphertext, privateKeyB)
    if msg:
        print(f'Mensagem original:: {msg}')
    else:
        print(f'Erro na descriptografia!')

    # # #
    print(" ")
    print("- - - - - - - - -")
    print("Respondendo...")
    message = "Tudo bem???"
    if (len(message) <= (bits / 8) - 11):
        print(f'Enviando mensagem: {message}...')
        print("Para: PARTE A")
    else:
        print("Mensagem muito grande...")

    ciphertext = encryptMessage(message, publicKeyA)

    # # #
    print(" ")
    print("Olá, parte A, você recebeu uma mensagem...")
    print("De: PARTE B")
    print(ciphertext)
    print("\nDescriptografando a mensagem...")

    msg = decryptMessage(ciphertext, privateKeyA)
    if msg:
        print(f'Mensagem original:: {msg}')
    else:
        print(f'Erro na descriptografia!')


#  file1 = os.path.join(newDir, "a.txt")
#         dsStore = os.path.join(newDir, ".DS_Store")
#         print(os.listdir(newDir))
#         if os.path.exists(file1):
#             print("Existe uma chave na pasta, removendo...")
#             os.remove(file1)
#         if os.path.exists(dsStore):
#             print("Existe uma chave na pasta, removendo...")
#             os.remove(dsStore)
#         os.rmdir(newDir)
#         dirc = "keys"
#         newDir = os.path.join(parentDir, dirc)
#         os.mkdir(newDir)

    # Deve assinar usando sua chave privada, para que todos possam descriptografar usando a chave publica

    # signature = sign(message, privateKey)
    # print(f'Signature (HASH): {signature.hex()} \n')

    # if verify(msg, signature, publicKey):
    #     print('Successfully verified signature \n')
    # else:
    #     print('The message signature could not be verified')
