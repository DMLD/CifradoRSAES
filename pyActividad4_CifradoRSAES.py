from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generar_par_claves_rsa():
    """Genera un par de claves RSA (pública y privada)"""
    clave_privada = RSA.generate(2048)
    clave_publica = clave_privada.publickey()
    return clave_publica, clave_privada

def cifrar_aes(mensaje):
    """Cifra un mensaje usando AES-256-CBC"""
    # Generar clave AES aleatoria (32 bytes = 256 bits)
    clave_aes = get_random_bytes(32)
    # Generar Vector
    iv = get_random_bytes(AES.block_size)
    
    # Crear cifrador AES
    cifrador = AES.new(clave_aes, AES.MODE_CBC, iv)
    
    # Aplicar padding y cifrar
    mensaje_cifrado = cifrador.encrypt(pad(mensaje.encode('utf-8'), AES.block_size))
    
    return iv, mensaje_cifrado, clave_aes

def cifrar_clave_aes_rsa(clave_aes, clave_publica_rsa):
    """Cifra la clave AES usando RSA"""
    cifrador_rsa = PKCS1_OAEP.new(clave_publica_rsa)
    clave_aes_cifrada = cifrador_rsa.encrypt(clave_aes)
    return clave_aes_cifrada

def descifrar_clave_aes_rsa(clave_aes_cifrada, clave_privada_rsa):
    """Descifra la clave AES usando RSA"""
    descifrador_rsa = PKCS1_OAEP.new(clave_privada_rsa)
    clave_aes = descifrador_rsa.decrypt(clave_aes_cifrada)
    return clave_aes

def descifrar_aes(iv, mensaje_cifrado, clave_aes):
    """Descifra un mensaje usando AES"""
    descifrador = AES.new(clave_aes, AES.MODE_CBC, iv)
    mensaje_descifrado = unpad(descifrador.decrypt(mensaje_cifrado), AES.block_size)
    return mensaje_descifrado.decode('utf-8')

def mostrar_menu():
    print("\n=== MENÚ PRINCIPAL ===")
    print("1. Cifrar mensaje (AES + RSA)")
    print("2. Descifrar mensaje")
    print("3. Salir")
    return input("Seleccione una opción: ")

def main():
    # Generar par de claves RSA al inicio
    clave_publica, clave_privada = generar_par_claves_rsa()
    
    datos_cifrados = None
    
    while True:
        opcion = mostrar_menu()
        
        if opcion == "1":
            # Cifrar mensaje
            print("\n=== CIFRADO DE MENSAJE ===")
            mensaje = input("Ingrese el mensaje a cifrar: ")
            
            if not mensaje:
                print("Error: El mensaje no puede estar vacío")
                continue
            
            # Paso 1: Cifrar el mensaje con AES
            print("\n1. Cifrando mensaje con AES-256...")
            iv, mensaje_cifrado, clave_aes = cifrar_aes(mensaje)
            print(f" - Clave AES generada: {base64.b64encode(clave_aes).decode('utf-8')}")
            print(f" - IV generado: {base64.b64encode(iv).decode('utf-8')}")
            print(f" - Mensaje cifrado (Base64): {base64.b64encode(mensaje_cifrado).decode('utf-8')}")
            
            # Paso 2: Cifrar la clave AES con RSA
            print("\n2. Cifrando clave AES con RSA...")
            clave_aes_cifrada = cifrar_clave_aes_rsa(clave_aes, clave_publica)
            print(f" - Clave AES cifrada (Base64): {base64.b64encode(clave_aes_cifrada).decode('utf-8')}")
            
            # Almacenar datos para el descifrado
            datos_cifrados = {
                'iv': iv,
                'mensaje_cifrado': mensaje_cifrado,
                'clave_aes_cifrada': clave_aes_cifrada
            }
            
            print("\n✓ Mensaje cifrado exitosamente!")
            
        elif opcion == "2":
            if not datos_cifrados:
                print("Error: No hay mensajes cifrados almacenados")
                continue
                
            print("\n=== DESCIFRADO DE MENSAJE ===")
            
            # Paso 1: Descifrar la clave AES con RSA
            print("\n1. Descifrando clave AES con RSA...")
            clave_aes = descifrar_clave_aes_rsa(datos_cifrados['clave_aes_cifrada'], clave_privada)
            print(f" - Clave AES descifrada: {base64.b64encode(clave_aes).decode('utf-8')}")
            
            # Paso 2: Descifrar el mensaje con AES
            print("\n2. Descifrando mensaje con AES-256...")
            mensaje_original = descifrar_aes(
                datos_cifrados['iv'],
                datos_cifrados['mensaje_cifrado'],
                clave_aes
            )
            print(f" - IV usado: {base64.b64encode(datos_cifrados['iv']).decode('utf-8')}")
            print(f"\n✓ Mensaje original: {mensaje_original}")
            
        elif opcion == "3":
            print("Saliendo del programa...")
            break
            
        else:
            print("Opción no válida. Intente nuevamente.")

if __name__ == "__main__":
    main()