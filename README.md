# Proyectito-Python
# Codificador y Decodificador de Texto

**Codificador y Decodificador de Texto** es una aplicación de escritorio en Python que permite cifrar y descifrar texto utilizando varios métodos de codificación. Los usuarios pueden cargar archivos, introducir texto manualmente y aplicar los siguientes métodos de cifrado/descifrado:

- Cifrado César
- Cifrado Binario
- Cifrado Hexadecimal
- Cifrado Base64
- Cifrado AES

Además, la aplicación permite cambiar de tema y configurar parámetros a través de un archivo `config.ini`.

## Características

- **Cifrado César**: Aplica un desplazamiento a las letras del texto para cifrarlo.
- **Codificación Binaria**: Convierte el texto a su representación binaria.
- **Codificación Hexadecimal**: Convierte el texto a formato hexadecimal.
- **Codificación Base64**: Convierte el texto a su formato Base64.
- **Cifrado AES**: Utiliza el algoritmo AES para cifrar y descifrar texto de manera segura.
- **Interfaz gráfica**: Desarrollada con Tkinter, fácil de usar.
- **Cambio de temas**: Permite cambiar entre temas claros y oscuros.
- **Cargar y guardar archivos**: Los usuarios pueden cargar un archivo de texto para cifrar/descifrar.

## Requisitos

- **Python 3.x**: Asegúrate de tener instalado Python 3 en tu sistema.
- **Dependencias**: Instala las siguientes bibliotecas necesarias:

```bash
pip install pycryptodome
pip install tkinter
