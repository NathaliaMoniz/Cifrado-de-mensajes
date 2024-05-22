# Proyecto de Criptografía

Este proyecto implementa una aplicación de criptografía que permite la autenticación de usuarios, el envío y la recepción de coordenadas cifradas, y la verificación de firmas digitales y certificados. El proyecto está desarrollado en Python y utiliza la biblioteca cryptography para las operaciones criptográficas. También emplea PySimpleGUI para la interfaz gráfica y pandas para la manipulación de datos en archivos Excel.

## Descripción

La aplicación principal proporciona una interfaz gráfica para que los usuarios se autentiquen con su nickname y contraseña. Una vez autenticados, los usuarios pueden optar por enviar o recibir coordenadas cifradas. Las coordenadas son firmadas digitalmente y enviadas a otros usuarios utilizando cifrado simétrico y asimétrico.

## Funcionalidades

- **Autenticación de usuarios:** Los usuarios se autentican mediante nickname y contraseña, que se verifica contra una base de datos.
- **Envío de coordenadas cifradas:** Los usuarios pueden enviar coordenadas cifradas a otros usuarios. Las coordenadas son cifradas con una clave simétrica y firmadas digitalmente.
- **Recepción de coordenadas cifradas:** Los usuarios pueden recibir coordenadas cifradas, que son descifradas y verificadas utilizando las claves públicas y privadas almacenadas.
- **Verificación de firmas digitales:** La aplicación verifica la validez de las firmas digitales de los mensajes recibidos.
- **Verificación de certificados:** La aplicación valida la cadena de certificados utilizando una jerarquía de autoridades certificadoras (CA).

## Estructura del Proyecto

- **datos_cripto.xlsx:** Contiene información de los usuarios, incluyendo nicknames, contraseñas cifradas y claves públicas.
- **Coordenadas.xlsx:** Almacena las coordenadas cifradas, las claves simétricas cifradas, firmas y el emisor.
- **Claves_privadas.xlsx:** Contiene las claves privadas de los usuarios.
- **Autoridades.xlsx:** Contiene las claves privadas de las autoridades certificadoras.
- **Claves_publicas_autoridades.xlsx:** Almacena las claves públicas y certificados de las autoridades certificadoras.

# config_database.py

Este archivo contiene código comentado para la configuración inicial de las bases de datos:

- **Cifrado de contraseñas.**
- **Generación de claves privadas y públicas para los usuarios.**
- **Generación de certificados autofirmados y solicitudes de certificados (CSR).**

## Configuración y Ejecución

### Requisitos

- Python 3.8 o superior
- Bibliotecas de Python:
  - cryptography
  - pandas
  - PySimpleGUI
  - openpyxl

## Ejecución de la Aplicación

Para ejecutar el archivo principal, utiliza el siguiente comando en la terminal:

```bash
python main.py
```

# Uso

El uso de la aplicación sigue los siguientes pasos:

1. **Autenticación**: El usuario se autentica ingresando su nombre de usuario y contraseña.

2. **Selección de Acción**: Después de autenticarse, el usuario puede elegir entre enviar o recibir coordenadas.

3. **Envío de Coordenadas**: Cuando elige enviar coordenadas, el usuario ingresa el nombre del receptor y las coordenadas. Estos datos son cifrados y firmados digitalmente antes de ser enviados.

4. **Recepción de Coordenadas**: Cuando elige recibir coordenadas, el usuario descifra las coordenadas recibidas y verifica la firma digital del emisor para asegurar la autenticidad de los datos.
  
