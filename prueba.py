"""
Programa que implementa algoritmos post-cuánticos de firma digital y encapsulación de claves.

Este programa utiliza la biblioteca OQS (Open Quantum Safe) para acceder a los algoritmos criptográficos post-cuánticos.
Se utiliza el wrapper liboqs-python para acceder a las funciones de la biblioteca desarrolladas para el lenguaje C

Se incluyen las siguientes funciones:

- ML-KEM: Realiza el proceso de encapsulación de claves utilizando el algoritmo ML-KEM.
- ML-DSA: Realiza el proceso de firma digital utilizando el esquema ML-DSA.
- SLH-DSA: Realiza el proceso de firma digital utilizando el esquema de SPHINCS.

"""

import oqs
import time

def display_menu():
    """
    Despliegue de menú principal
    """
    print("Selecciona una opción:")
    print("1. ML-KEM")
    print("2. ML-DSA Signature")
    print("3. SLH-DSA Signature")
    print("4. Salir")

def display_kemSubMenu():
    """
    Despliegue del menú para ML-KEM
    """
    print("Selecciona el parametro a utilizar:")
    print("1. ML-KEM-512")
    print("2. ML-KEM-768")
    print("3. ML-KEM-1024")

def display_MLSubMenu():
    """
    Despliegue del menú para ML-DSA
    """
    print("Selecciona el parametro a utilizar:")
    print("1. ML-DSA-44")
    print("2. ML-DSA-65")
    print("3. ML-DSA-87")

def ml_kem(parametro):
    """
    Realiza el proceso de ML-KEM.

    Args:
        parametro (str): El parámetro seleccionado del submenú.

    Returns:
        None
    """
    if parametro == '1':
        param = 'ML-KEM-512'
        print("Usando ML-KEM-512...")
    elif parametro == '2':
        param = 'ML-KEM-768'
        print("Usando ML-KEM-768...")
    elif parametro == '3':
        param = 'ML-KEM-1024'
        print("Usando ML-KEM-1024...")

    #    Se establece un contexto para la encapsulación de claves del cliente utilizando el parámetro dado
    with oqs.KeyEncapsulation(param) as client:
        #    Se establece un contexto para la encapsulación de claves del servidor utilizando el parámetro dado
        with oqs.KeyEncapsulation(param) as server:
            start_time = time.time()

            #Generación del par de claves para el cliente
            public_key_client = client.generate_keypair()
            #Encapsulación de la clave en el servidor utilizando la clave pública del cliente
            ciphertext, shared_secret_server = server.encap_secret(public_key_client)
            #Realiza la desencapsulación de la clave en el cliente utilizando el texto cifrado recibido del servidor
            shared_secret_client = client.decap_secret(ciphertext)

            end_time = time.time()
            #Medición del tiempo de ejecución para evaluar el algoritmo
            execution_time = end_time - start_time

            print(f"Tiempo de ejecución: {execution_time} segundos")
            print("llave desencapsulada de A:",shared_secret_client)
            print("Llave encapsulada de B:", shared_secret_server)
            print("Generación exitosa de llave secreta compartida:", shared_secret_client == shared_secret_server,"\n")
            

def ml_dsa_signature(parametro):
    """
    Realiza el proceso de firma digital utilizando el esquema ML-DSA.

    Args:
        parametro (str): Parámetro seleccionado del menú para determinar el tamaño de la clave

    Returns:
        None
    """

    if parametro == '1':
        param = "ML-DSA-44"
        print("Usando ML-KEM-512...")
    elif parametro == '2':
        param = "ML-DSA-65"
        print("Usando ML-KEM-768...")
    elif parametro == '3':
        param = "ML-DSA-87"
        print("Usando ML-KEM-1024...")
    texto = input("Introduce el mensaje de prueba: ")
    texto = texto.encode()

    #Se establece un contexto para la generación de la firma digital
    with oqs.Signature(param) as signer:
        #Establece un contexto para la verificación de la firma digital
        with oqs.Signature(param) as verifier:
            start_time = time.time()

            #Se gegnera un par de claves para quien realiza la firma digital
            signer_public_key = signer.generate_keypair()
            #Se realiza la firma digital para el texto introducido
            signature = signer.sign(texto)

            end_time = time.time()
            #Medición del tiempo de ejecución para evaluar el algoritmo
            execution_time = end_time - start_time
            
            #Se verifica la firma digital
            is_valid = verifier.verify(texto, signature, signer_public_key)
            print("Firma valida a  través de ML-DSA-44:", is_valid)
            print(f"Tiempo de ejecución: {execution_time} segundos")

def slh_dsa_signature():
     """
    Realiza el proceso de firma digital utilizando el esquema de SPHINCS

    Solicita al usuario un mensaje de prueba, genera una firma digital para el mensaje 
    y posteriormente se verifica la autenticidad de la firma

    Args:
        None

    Returns:
        None
    """
    param = "SPHINCS+-SHA2-128f-simple"
    texto = input("Introduce el mensaje de prueba: ")
    texto = texto.encode()

    #Se establece un contexto para la generación de la firma digital
    with oqs.Signature(param) as signer:
        #Se establece un contexto para la verificación de la firma digital
        with oqs.Signature(param) as verifier:
            start_time = time.time()
            #Se genera par de claves para quien realiza la firma digital
            signer_public_key = signer.generate_keypair()
            #Se firma el texto
            signature = signer.sign(texto)
            
            end_time = time.time()
            #Medición del tiempo de ejecución para evaluar el algoritmo
            execution_time = end_time - start_time
            #Se verifica la firma digital
            is_valid = verifier.verify(texto, signature, signer_public_key)
            print("Firma valida a  través de SPHINCS+-SHA2-128f-simple:", is_valid)
            print(f"Tiempo de ejecución: {execution_time} segundos")

def main():
    """
    Función principal
    Muestra un menú de opciones al usuario y realiza las diferentes funciones criptográficas post-cuánticas

    Args:
        None

    Returns:
        None
    """
    while True:
        display_menu()
        choice = input("Introduce tu elección: ")

        #Opción para realizar ML-KEM
        if choice == '1':
            display_kemSubMenu()
            sub_choice = input("Introduce tu elección: ")
            ml_kem(sub_choice)
        #Opción para realizar ML-DSA
        elif choice == '2':
            display_MLSubMenu()
            sub_choice = input("Introduce tu elección: ")
            ml_dsa_signature(sub_choice)
        #Opción para realilzar SLH-DSA
        elif choice == '3':
            slh_dsa_signature()
        #Opción para salir del programa
        elif choice == '4':
            print("Saliendo del programa...")
            break
        else:
            print("Opción no válida. Por favor, intenta de nuevo.")

if __name__ == "__main__":
    main()
