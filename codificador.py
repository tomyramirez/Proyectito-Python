import tkinter as tk
from tkinter import filedialog, messagebox
import os
import base64
import binascii
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import configparser  # Módulo para leer y escribir archivos INI

# Variable global para almacenar la clave AES
clave_global_aes = None

# Variables globales para los temas
tema_oscuro = {
    "bg": "#2e3b4e",
    "fg": "white",
    "boton_bg": "#4a596e",
    "texto_bg": "#3c4a5a",
    "insert_bg": "white"
}

tema_claro = {
    "bg": "#f0f0f0",
    "fg": "black",
    "boton_bg": "#dcdcdc",
    "texto_bg": "#ffffff",
    "insert_bg": "black"
}

# Cargar la configuración desde el archivo INI
config = configparser.ConfigParser()
config.read('config.ini')

# Leer el tema actual desde el archivo de configuración
tema_seleccionado = config.get('General', 'tema', fallback='oscuro')

# Variables para el tema actual
tema_actual = tema_oscuro if tema_seleccionado == 'oscuro' else tema_claro

# Función para cambiar el tema
def cambiar_tema(tema):
    global tema_actual
    if tema == "oscuro":
        tema_actual = tema_oscuro
    else:
        tema_actual = tema_claro

    ventana.config(bg=tema_actual["bg"])
    label_archivo.config(fg=tema_actual["fg"], bg=tema_actual["bg"])
    boton_cargar.config(bg=tema_actual["boton_bg"], fg=tema_actual["fg"])
    entrada_texto.config(bg=tema_actual["texto_bg"], fg=tema_actual["fg"], insertbackground=tema_actual["insert_bg"])
    entrada_desplazamiento.config(bg=tema_actual["texto_bg"], fg=tema_actual["fg"])
    resultado_texto.config(bg=tema_actual["texto_bg"], fg=tema_actual["fg"], insertbackground=tema_actual["insert_bg"])
    for widget in frame_codificar.winfo_children():
        widget.config(bg=tema_actual["boton_bg"], fg=tema_actual["fg"])
    for widget in frame_decodificar.winfo_children():
        widget.config(bg=tema_actual["boton_bg"], fg=tema_actual["fg"])

    # Guardar el tema seleccionado en el archivo de configuración
    config.set('General', 'tema', tema)
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

# Función para cargar un archivo de texto
def cargar_archivo():
    archivo = filedialog.askopenfilename(
        title="Seleccionar archivo",
        filetypes=(("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*"))
    )
    if archivo:
        with open(archivo, 'r', encoding='utf-8') as file:
            texto_cargado = file.read()
        entrada_texto.delete(1.0, tk.END)
        entrada_texto.insert(tk.END, texto_cargado)
        label_archivo.config(text=f"Archivo cargado: {os.path.basename(archivo)}")
    else:
        messagebox.showwarning("Advertencia", "No se ha seleccionado ningún archivo")

# Funciones para codificar en diferentes métodos

def codificar_cesar():
    try:
        desplazamiento = int(entrada_desplazamiento.get())
        texto = entrada_texto.get(1.0, tk.END).strip()
        if texto:
            texto_codificado = codificar(texto, desplazamiento)
            mostrar_resultado(texto_codificado)
        else:
            messagebox.showwarning("Advertencia", "No hay texto para codificar")
    except ValueError:
        messagebox.showerror("Error", "El desplazamiento debe ser un número entero")

def decodificar_cesar():
    try:
        desplazamiento = int(entrada_desplazamiento.get())
        texto = entrada_texto.get(1.0, tk.END).strip()
        if texto:
            texto_decodificado = decodificar(texto, desplazamiento)
            mostrar_resultado(texto_decodificado)
        else:
            messagebox.showwarning("Advertencia", "No hay texto para decodificar")
    except ValueError:
        messagebox.showerror("Error", "El desplazamiento debe ser un número entero")

def codificar_binario():
    texto = entrada_texto.get(1.0, tk.END).strip()
    if (texto):
        texto_binario = ' '.join(format(ord(c), '08b') for c in texto)
        mostrar_resultado(texto_binario)
    else:
        messagebox.showwarning("Advertencia", "No hay texto para codificar")

def decodificar_binario():
    texto = entrada_texto.get(1.0, tk.END).strip()
    if texto:
        try:
            texto_decodificado = ''.join([chr(int(bin_char, 2)) for bin_char in texto.split()])
            mostrar_resultado(texto_decodificado)
        except ValueError:
            messagebox.showerror("Error", "Texto binario no válido")
    else:
        messagebox.showwarning("Advertencia", "No hay texto para decodificar")

def codificar_hexadecimal():
    texto = entrada_texto.get(1.0, tk.END).strip()
    if texto:
        texto_hex = texto.encode('utf-8').hex()
        mostrar_resultado(texto_hex)
    else:
        messagebox.showwarning("Advertencia", "No hay texto para codificar")

def decodificar_hexadecimal():
    texto = entrada_texto.get(1.0, tk.END).strip()
    if texto:
        try:
            texto_decodificado = bytes.fromhex(texto).decode('utf-8')
            mostrar_resultado(texto_decodificado)
        except ValueError:
            messagebox.showerror("Error", "Texto hexadecimal no válido")
    else:
        messagebox.showwarning("Advertencia", "No hay texto para decodificar")

def codificar_base64():
    texto = entrada_texto.get(1.0, tk.END).strip()
    if texto:
        texto_base64 = base64.b64encode(texto.encode('utf-8')).decode('utf-8')
        mostrar_resultado(texto_base64)
    else:
        messagebox.showwarning("Advertencia", "No hay texto para codificar")

def decodificar_base64():
    texto = entrada_texto.get(1.0, tk.END).strip()
    if texto:
        try:
            texto_decodificado = base64.b64decode(texto).decode('utf-8')
            mostrar_resultado(texto_decodificado)
        except binascii.Error:
            messagebox.showerror("Error", "Texto Base64 no válido")
    else:
        messagebox.showwarning("Advertencia", "No hay texto para decodificar")

# AES codificación y decodificación
def codificar_aes():
    global clave_global_aes  # Almacenar la clave globalmente
    texto = entrada_texto.get(1.0, tk.END).strip()
    if texto:
        try:
            key = get_random_bytes(16)  # Generamos una clave de 128 bits
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(texto.encode('utf-8'), AES.block_size))
            resultado_aes = base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
            mostrar_resultado(resultado_aes)
            label_archivo.config(text=f"Clave AES: {key.hex()}")
            clave_global_aes = key  # Almacenar la clave para decodificar después
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Advertencia", "No hay texto para codificar")

def decodificar_aes():
    global clave_global_aes  # Usar la clave almacenada
    texto = entrada_texto.get(1.0, tk.END).strip()
    if texto and clave_global_aes:
        try:
            texto_cifrado = base64.b64decode(texto)
            iv = texto_cifrado[:16]
            ciphertext = texto_cifrado[16:]
            cipher = AES.new(clave_global_aes, AES.MODE_CBC, iv)
            texto_decodificado = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
            mostrar_resultado(texto_decodificado)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Advertencia", "Texto o clave AES no proporcionados")

# Función para mostrar el resultado en la interfaz
def mostrar_resultado(texto):
    resultado_texto.delete(1.0, tk.END)
    resultado_texto.insert(tk.END, texto)

# Funciones del cifrado César
def codificar(texto, desplazamiento):
    texto_codificado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            texto_codificado += chr((ord(caracter) - base + desplazamiento) % 26 + base)
        else:
            texto_codificado += caracter
    return texto_codificado

def decodificar(texto, desplazamiento):
    return codificar(texto, -desplazamiento)

# Interfaz gráfica con Tkinter
ventana = tk.Tk()
ventana.title("Codificador y Decodificador de Texto")
ventana.geometry("1200x600")
ventana.config(bg=tema_actual["bg"])

# Menú
barra_herramientas = tk.Menu(ventana)
ventana.config(menu=barra_herramientas)

menu_tema = tk.Menu(barra_herramientas, tearoff=0)
barra_herramientas.add_cascade(label="Tema", menu=menu_tema)
menu_tema.add_command(label="Oscuro", command=lambda: cambiar_tema("oscuro"))
menu_tema.add_command(label="Claro", command=lambda: cambiar_tema("claro"))

# Etiquetas y entradas
label_archivo = tk.Label(ventana, text="No se ha cargado ningún archivo", fg=tema_actual["fg"], bg=tema_actual["bg"])
label_archivo.pack(pady=5)

boton_cargar = tk.Button(ventana, text="Cargar archivo de texto", command=cargar_archivo, bg=tema_actual["boton_bg"], fg=tema_actual["fg"])
boton_cargar.pack(pady=5)

tk.Label(ventana, text="Texto cargado:", fg=tema_actual["fg"], bg=tema_actual["bg"]).pack(pady=5)
entrada_texto = tk.Text(ventana, height=10, width=50, bg=tema_actual["texto_bg"], fg=tema_actual["fg"], insertbackground=tema_actual["insert_bg"])
entrada_texto.pack(pady=5)

tk.Label(ventana, text="Desplazamiento para cifrado César:", fg=tema_actual["fg"], bg=tema_actual["bg"]).pack(pady=5)
entrada_desplazamiento = tk.Entry(ventana, bg=tema_actual["texto_bg"], fg=tema_actual["fg"])
entrada_desplazamiento.pack(pady=5)

# Botones para cada método de codificación/decodificación
frame_codificar = tk.Frame(ventana, bg=tema_actual["bg"])
frame_codificar.pack(pady=10)

tk.Button(frame_codificar, text="Codificar César", command=codificar_cesar, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=0, padx=5, pady=5)
tk.Button(frame_codificar, text="Codificar Binario", command=codificar_binario, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=1, padx=5, pady=5)
tk.Button(frame_codificar, text="Codificar Hexadecimal", command=codificar_hexadecimal, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=2, padx=5, pady=5)
tk.Button(frame_codificar, text="Codificar Base64", command=codificar_base64, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=3, padx=5, pady=5)
tk.Button(frame_codificar, text="Codificar AES", command=codificar_aes, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=4, padx=5, pady=5)

# Frame de botones de decodificación
frame_decodificar = tk.Frame(ventana, bg=tema_actual["bg"])
frame_decodificar.pack(pady=10)

tk.Button(frame_decodificar, text="Decodificar César", command=decodificar_cesar, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=0, padx=5, pady=5)
tk.Button(frame_decodificar, text="Decodificar Binario", command=decodificar_binario, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=1, padx=5, pady=5)
tk.Button(frame_decodificar, text="Decodificar Hexadecimal", command=decodificar_hexadecimal, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=2, padx=5, pady=5)
tk.Button(frame_decodificar, text="Decodificar Base64", command=decodificar_base64, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=3, padx=5, pady=5)
tk.Button(frame_decodificar, text="Decodificar AES", command=decodificar_aes, bg=tema_actual["boton_bg"], fg=tema_actual["fg"]).grid(row=0, column=4, padx=5, pady=5)

# Resultado
tk.Label(ventana, text="Resultado:", fg=tema_actual["fg"], bg=tema_actual["bg"]).pack(pady=5)
resultado_texto = tk.Text(ventana, height=10, width=50, bg=tema_actual["texto_bg"], fg=tema_actual["fg"], insertbackground=tema_actual["insert_bg"])
resultado_texto.pack(pady=5)

# Ejecutar la ventana principal
ventana.mainloop()
