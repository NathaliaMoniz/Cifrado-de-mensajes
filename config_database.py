import os
import re
import ast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
import pandas as pd
import PySimpleGUI as sg
import datetime

data_frame = pd.read_excel("./datos_cripto.xlsx")
data_frame2 = pd.read_excel("./Coordenadas.xlsx")
data_frame3 = pd.read_excel("./Claves_privadas.xlsx")
data_frame4 = pd.read_excel("./Autoridades.xlsx")
data_frame5 = pd.read_excel("./Claves_publicas_autoridades.xlsx")

#CODIGO PARA ENCRIPTAR LAS CONTRASEÑAS
"""for index, row in data_frame.iterrows():
    salt = os.urandom(16)
    contraseña = row['Contraseña']
    contraseña_bytes = contraseña.encode('utf-8')
    data_frame.at[index, 'Salt'] = salt
    data_frame.to_excel('./datos_cripto.xlsx', index=False)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(contraseña_bytes)
    data_frame.at[index, 'Key'] = key
    data_frame.to_excel('./datos_cripto.xlsx', index=False)"""

#CODIGO PARA GENERAR LAS CLAVES PRIVADAS DE CADA USUARIO 
"""for index, row in data_frame3.iterrows():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )
    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    pem.splitlines()[0]
    data_frame3.at[index, 'Privadas'] = pem
    data_frame3.to_excel('./Claves_privadas.xlsx', index=False)"""

#CODIGO PARA OBTENER LA CALVE PÚBLICA DE CADA USUARIO Y GUARDARLA EN LA BASE DE DATOS
"""for index, row in data_frame.iterrows():
    nickname1 = row['Nickname']
    for index, row in data_frame3.iterrows():
        nickname2 = row['Nickname']
        privada = row['Privadas']
        privada_pem = serialization.load_pem_private_key(ast.literal_eval(privada), password=None)
        if nickname1 == nickname2:
            public_key = privada_pem.public_key()
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pem_public.splitlines()[0]
            data_frame.at[index, 'Key_public'] = pem_public  
            data_frame.to_excel('./datos_cripto.xlsx', index=False)"""

#GENERACIÓN DE CLAVES PRIVADAS DE LOS CA
"""for index, row in data_frame4.iterrows():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )
    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    pem.splitlines()[0]
    data_frame4.at[index, 'Privada'] = pem
    data_frame4.to_excel('./Autoridades.xlsx', index=False)"""

# GENERACIÓN DE CLAVE PÚBLICA DE LOS CA
"""for index, row in data_frame4.iterrows():
    nickname1 = row['Autoridad']       
    privada = row['Privada']
    privada_pem = serialization.load_pem_private_key(ast.literal_eval(privada), password=None)
    
    public_key = privada_pem.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_public.splitlines()[0]
    data_frame5.at[index, 'Publica'] = pem_public  
    data_frame5.to_excel('./claves_publicas_autoridades.xlsx', index=False)"""

# CÓDIGO PARA GENERAR EL CERTIFICADO AUTOFIRMADO DE LA ENTIDAD RAÍZ Y GENERAR LAS CSR
"""for index, row in data_frame4.iterrows():
    privada_autoridad = row["Privada"] 
    autoridad_nombre = row["Autoridad"]
    numero = 1
    if autoridad_nombre == "Máxima":
        privada_raiz = row["Privada"] 
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "East Blue"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "La mar"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Barba Negra Corp."),
        ])
        privada_autoridad_pem = serialization.load_pem_private_key(ast.literal_eval(privada_autoridad), password=None)
        certificado_raiz = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            privada_autoridad_pem.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(privada_autoridad_pem, hashes.SHA256())

        data_frame5.at[index, 'Certificado'] = certificado_raiz
        data_frame5.to_excel('./Claves_publicas_autoridades.xlsx', index=False)
    else:
        privada_autoridad_pem = serialization.load_pem_private_key(ast.literal_eval(privada_autoridad), password=None)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "North Blue"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "La mar del norte"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Subordinada corp." + str(numero)),
        ])).add_extension(
            x509.SubjectAlternativeName([
            ]),
            critical=False,

        ).sign(privada_autoridad_pem, hashes.SHA256())
        numero += 1
        csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

        subordinada_certificado = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            certificado_raiz.subject  
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        ).sign(serialization.load_pem_private_key(ast.literal_eval(privada_raiz), password=None), hashes.SHA256(), default_backend())

        subordinada_certificado_pem = subordinada_certificado.public_bytes(serialization.Encoding.PEM)
        data_frame5.at[index, 'solicitud'] = csr_pem  
        data_frame5.to_excel('./Claves_publicas_autoridades.xlsx', index=False)
        data_frame5.at[index, 'Certificado'] = subordinada_certificado_pem
        data_frame5.to_excel('./Claves_publicas_autoridades.xlsx', index=False)"""

# CODIGO PARA CREAR LOS CSR DE LOS USUARIOS Y LOS CERTIFICADOS
"""for index_usuario, row_usuario in data_frame3.iterrows():
    privada_usuario = row_usuario["Privadas"] 
    nombre_usuario = row_usuario["Nickname"]
    autoridad_usuario = row_usuario["Entidad"]
    for index_entidad, row_entidad in data_frame4.iterrows():
        entidad = row_entidad["Autoridad"]
        privada_autoridad = row_entidad["Privada"]
        certificado_autoridad = row_entidad["Certificado"]
        
        if autoridad_usuario == 1 and entidad == "Subordinada_1":
            print("all")
            certificado_autoridad_pem = x509.load_pem_x509_certificate(ast.literal_eval(certificado_autoridad), default_backend())
            privada_usuario_pem = serialization.load_pem_private_key(ast.literal_eval(privada_usuario), password=None)
            subject_usuario = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Thousand Sunny"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "La mar"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Piratas anónimos"),
                x509.NameAttribute(NameOID.COMMON_NAME, nombre_usuario),
            ])
            csr_usuario = x509.CertificateSigningRequestBuilder().subject_name(
                subject_usuario
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(privada_usuario_pem, hashes.SHA256(), default_backend())

            data_frame.at[index_usuario, 'Solicitud'] = csr_usuario.public_bytes(serialization.Encoding.PEM)
            data_frame.to_excel('./datos_cripto.xlsx', index=False)
            
            certificado_usuario = x509.CertificateBuilder().subject_name(
                subject_usuario
            ).issuer_name(
                certificado_autoridad_pem.subject  # El usuario es su propio emisor en este ejemplo
            ).public_key(
                csr_usuario.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(serialization.load_pem_private_key(ast.literal_eval(privada_autoridad), password=None), hashes.SHA256())

            data_frame.at[index_usuario, 'Certificado'] = certificado_usuario.public_bytes(serialization.Encoding.PEM)
            data_frame.to_excel('./datos_cripto.xlsx', index=False)
        
        elif autoridad_usuario == 2 and entidad == "Subordinada_2":
            certificado_autoridad_pem = x509.load_pem_x509_certificate(ast.literal_eval(certificado_autoridad), default_backend())
            privada_usuario_pem = serialization.load_pem_private_key(ast.literal_eval(privada_usuario), password=None)
            subject_usuario = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Thousand Sunny"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "La mar"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Piratas anónimos"),
                x509.NameAttribute(NameOID.COMMON_NAME, nombre_usuario),
            ])
            csr_usuario = x509.CertificateSigningRequestBuilder().subject_name(
                subject_usuario
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(privada_usuario_pem, hashes.SHA256(), default_backend())

            data_frame.at[index_usuario, 'Solicitud'] = csr_usuario.public_bytes(serialization.Encoding.PEM)
            data_frame.to_excel('./datos_cripto.xlsx', index=False)
            
            certificado_usuario = x509.CertificateBuilder().subject_name(
                subject_usuario
            ).issuer_name(
                certificado_autoridad_pem.subject  # El usuario es su propio emisor en este ejemplo
            ).public_key(
                csr_usuario.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(serialization.load_pem_private_key(ast.literal_eval(privada_autoridad), password=None), hashes.SHA256())

            data_frame.at[index_usuario, 'Certificado'] = certificado_usuario.public_bytes(serialization.Encoding.PEM)
            data_frame.to_excel('./datos_cripto.xlsx', index=False)"""