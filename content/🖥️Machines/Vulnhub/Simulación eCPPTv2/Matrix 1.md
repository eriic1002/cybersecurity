#ctf-machine #vulnhub #easy-machine #linux #simulacion-eccptv2  [[Simulation eCPPTv2 Map.canvas|Simulation eCPPTv2 Map]]

## Pivoting
Nos encontramos en la máquina 192.168.100.130 (Dumbledore). Si mostramos las interfaces de red, vemos una nueva:
![[Pasted image 20240830141017.png]]

Como vemos hay un segmento nuevo de red que no conocemos por lo que vamos a transferir `chisel` a la máquina víctima mediante el túnel del puerto 445 que hemos creado anteriormente. Por lo que primeramente ejecutamos el `smbserver` en nuestra máquina:
![[Pasted image 20240830163118.png]]

Y copiamos el archivo en la máquina Windows:
![[Pasted image 20240830163103.png]]

 Por lo que en la máquina Windows ejecutamos el `chisel` como cliente para conectarnos a la "192.168.100.128" por el puerto 12345:
![[Pasted image 20240830172326.png]]

Ahora en la "192.168.100.128" (10.10.0.129) le enviamos su tráfico por el puerto 12345 a la "10.10.0.128" por el puerto 12345 con `socat`:
![[Pasted image 20240830172625.png]]

Y finalmente, en la máquina "10.10.0.128" (192.168.159.147) enviamos su tráfico por el puerto 1234 a mi máquina por el puerto 1234.
![[Pasted image 20240830174341.png]]

Una vez conectado el *proxy* debemos de añadirlo a la configuración de `proxychains` en `/etc/proxychains4.conf`:
![[Pasted image 20240830182106.png]]

## Enumeración inicial
Podemos hacer un escaneo de *hosts* con este pequeño *script* que utiliza `ping` junto a `proxychains`:
```bash
for i in $(seq 1 254); do
  ping -c 1 172.18.0.$i -W 1 > /dev/null && echo "[+] Host 172.18.0.$i" &
done; wait
```

Por lo que si lo ejecutamos vemos los siguientes *hosts*:
![[Pasted image 20240830182306.png]]

Como vemos hay un *host* nuevo. Así que lanzamos un primer escaneo de puertos mediante `nmap` haciendo uso de `proxychains` y `args` para agilizar el escaneo:
![[Pasted image 20240830192141.png]]

## Enumeración web
Primeramente debemos añadir el nuevo *proxy* a `foxyproxy` para poder alcanzar a la web por lo que lo añadimos lo siguiente:
![[Pasted image 20240830183610.png]]

Una vez añadido si pasamos por el *proxy* y accedemos a la web vemos lo siguiente:
![[Pasted image 20240830183631.png]]

Como vemos no hay nada interesante así que hacemos un escaneo de directorios con `gobuster`, pero no encontramos nada. Por lo que accedemos a la web del puerto y vemos lo siguiente:
![[Pasted image 20240830192159.png]]

Si analizamos el código fuente, vemos el siguiente valor:
![[Pasted image 20240830192217.png]]

Que si lo decodificamos en base 64 vemos:
![[Pasted image 20240830192501.png]]

Si accedemos a `/Cypher.matrix` en la web, encontramos el siguiente archivo:
![[Pasted image 20240830192851.png]]

Como vemos es un código *brainfuck* por lo que si utilizamos el *decoder* *online* obtenemos:
```
You can enter into matrix as guest, with password k1ll0rXX

Note: Actually, I forget last two characters so I have replaced with XX try your luck and find correct string of password.
```


## RCE
Nos dice que podemos acceder a la máquina *brainfuck* como el usuario "guest" con la contraseña "k1ll0rXX" donde XX son caracteres desconocidos. Por lo que podemos mostrarnos un script en "bash" para generar todas las combinaciones de contraseña:
```bash
for i in $(seq 33 126); do 
  char1=$(printf "\\$(printf "%o" $i)")
  for j in $(seq 33 126); do
    char2=$(printf "\\$(printf "%o" $j)")
    echo "k1ll0r$char1$char2" >> wordlist.txt
  done
done
```

Una vez generado el diccionario, con `hydra` junto a `proxychains` hacemos fuerza bruta:
![[Pasted image 20240830201653.png]]

Como vemos tenemos la contraseña por lo que nos conectamos por SSH utilizando `proxychains`:
![[Pasted image 20240830213551.png]]

Pero estamos en una *restricted bash* por lo que podemos hacer *bypass* si nos volvemos a conectar poniendo "bash" al final:
![[Pasted image 20240830222655.png]]
![[Pasted image 20240830222724.png]]

Si listamos los permisos a nivel de *sudoers* vemos lo siguiente:
![[Pasted image 20240830223351.png]]

Por lo que si ejecutamos `sudo bash` obtenemos una "bash" como *root*:
![[Pasted image 20240830223517.png]]

Y si accedemos al directorio `/root` podemos visualizar la *flag*:
![[Pasted image 20240830223612.png]]

___
#abusing-sudoers #information-leakage 
___