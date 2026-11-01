# Honeypots Inteligentes: O uso de LLMs na análise de logs de honeypots para apoio à resposta a incidentes

Repositório com o código-fonte da prova de conceito desenvolvida para o Trabalho de Conclusão de Curso (TCC) de **Tecnologia em Segurança da Informação** da **FATEC Americana "Ministro Ralph Biasi"** (2026).

**Autores:**
- Gabriel Santos Saranço
- João Pedro Angioletti Rocha
- Kelvin Thierry Barros Miranda

**Orientador:** Prof. Esp. Alexandre Donizetti de Souza

---

## Sobre o Projeto

Servidores SSH expostos na internet recebem diariamente milhares de conexões automáticas de robôs (bots), o que dificulta encontrar manualmente ataques reais nos arquivos de log. 

Este projeto integra o honeypot SSH **Cowrie** (rodando em contêiner Docker) a um script em Python que faz a triagem automática das sessões em três passos:

1. **Agrupamento de Sessão:** lê o arquivo `cowrie.json`, junta os eventos de uma mesma conexão pelo código da sessão (`session`), oculta o IP do servidor local e calcula o intervalo de tempo entre os comandos digitados.
2. **Filtro Local de Ruído (Nível 1):** descarta acessos sem comandos pós-login e verifica se o IP de origem já consta na lista pública **IPsum** (base diária de IPs conhecidos por varreduras automáticas) ou se executou apenas comandos repetitivos de robôs (ex.: `uname -s -v -n -r -m`). Essas sessões já são marcadas localmente como `BOT_AUTOMATIZADO` sem gastar requisições da API.
3. **Análise com IA (Nível 2):** envia as sessões interativas ou inéditas para a API do modelo **Google Gemini 3.5 Flash-Lite** (`gemini-3.5-flash-lite`), que classifica a sessão entre `BOT_AUTOMATIZADO` e `ATAQUE_HUMANO_DIRECIONADO`, associa os comandos às técnicas do **MITRE ATT&CK** e sugere comandos de bloqueio para firewall (`iptables`).

---

## Estrutura de Arquivos

```text
.
├── docker-compose.yml      # Configuração do contêiner Docker do Cowrie (porta 22 -> 2222)
├── etc/
│   ├── cowrie.cfg          # Configuração principal do honeypot (SSH ativo e saída em JSON)
│   └── userdb.txt          # Regra de autenticação do honeypot para observar ações pós-login
├── triagem.py              # Script principal: agrupamento, filtro IPsum e análise no Gemini
├── avaliar_metricas.py     # Script de validação (30 sessões, ablação, generalização e 6 Prompt Injections)
├── resultados_validacao/   # Saídas cruas da API, funil de 30 dias, auditoria MITRE e mitigação (JSON)
│   ├── resumo_funil_30_dias.json                # Contagens exatas dos 30 dias (1.381.038 eventos / 170.891 sessões)
│   ├── coleta_30_dias_32_sessoes_l2_raw.json    # Saída crua das 32 sessões reais que avançaram ao Nível 2 (31 VN, 1 FP)
│   ├── validacao_30_sessoes_raw.json            # Saída crua das 30 sessões no LLM + conferencia_mitre + auditoria_mitigacao
│   ├── ablacao_prompt_neutro_30_sessoes_raw.json # Estudo de ablação nas 30 sessões com prompt neutro sem dicas (30/30)
│   ├── generalizacao_10_cenarios_raw.json       # Teste de generalização em 10 cenários inéditos fora do prompt (9/10 vs 10/10)
│   └── prompt_injection_6_variantes_raw.json    # Saída crua das 6 variantes de Prompt Injection (6/6 resistidas)
├── amostra_logs.json       # Amostra de logs com sessões de bots reais e ataques humanos simulados
├── relatorio_triagem.json  # Exemplo de relatório JSON gerado após rodar o triagem.py
└── .env.example            # Exemplo de configuração da variável GEMINI_API_KEY
```

---

## Pré-requisitos

- **Python 3.9+** (utiliza apenas bibliotecas nativas do Python, sem necessidade de instalar pacotes extras via `pip`)
- **Docker** e **Docker Compose** (para subir o honeypot Cowrie)
- Uma chave gratuita de API do **Google AI Studio** (`GEMINI_API_KEY`)

---

## Como Executar

### 1. Subir o Honeypot Cowrie (Opcional para testar apenas os logs)
```bash
docker compose up -d
```
> O `docker-compose.yml` redireciona a porta `22` externa do servidor para a porta `2222` interna do contêiner do Cowrie e salva os logs na pasta `./logs/cowrie/`.

### 2. Configurar a Chave da API do Gemini
Copie o arquivo `.env.example` para `.env` e coloque a sua chave do Google AI Studio:
```bash
cp .env.example .env
```
Ou exporte direto no terminal antes de rodar:
```bash
export GEMINI_API_KEY="sua_chave_aqui"
```

### 3. Executar a Triagem de Logs
Para testar com o arquivo de amostra que já vem no repositório (`amostra_logs.json`):
```bash
python3 triagem.py amostra_logs.json
```
Para analisar o arquivo de log real gerado pelo seu contêiner do Cowrie:
```bash
python3 triagem.py logs/cowrie/cowrie.json
```

**Exemplo de saída no terminal:**
```text
[1/6] Sessao 1fe070084516 | IP: 77.239.124.147 | Comandos: 1
   -> Classificacao: BOT_AUTOMATIZADO (Filtro Local L1 - 0.001s)
   -> Motivo: IP listado na base publica IPsum e comando padrao de bot.
   -> Bloqueio: iptables -A INPUT -s 77.239.124.147 -j DROP

[4/6] Sessao 350bf1bd00da | IP: 198.51.100.44 | Comandos: 9
   -> Classificacao: ATAQUE_HUMANO_DIRECIONADO (API Gemini - 1.98s)
   -> Risco: CRÍTICO | Resumo: Leitura de /etc/passwd e /etc/shadow, busca SUID, persistencia SSH e limpeza.
   -> MITRE ATT&CK: T1033, T1082, T1003.008, T1083, T1098.004, T1070.003
   -> Bloqueio: iptables -A INPUT -s 198.51.100.44 -j DROP
```
Ao final da execução, o relatório completo com todas as sessões analisadas é salvo no arquivo `relatorio_triagem.json`.

### 4. Reproduzir a Validação e a Matriz de Confusão (30 Sessões + Baseline + Prompt Injection)
Para rodar o teste de validação direta do modelo com as 30 sessões rotuladas do TCC (20 bots e 10 ataques humanos simulados), comparar com o baseline por regra simples (`>= 3 comandos distintos = humano`) e testar as 6 variantes de *Prompt Injection* (salvando as saídas cruas na pasta `resultados_validacao/`):
```bash
python3 avaliar_metricas.py
```

**Saída esperada da validação:**
```text
=== RESULTADO DA MATRIZ DE CONFUSAO (N = 30 DIRETAS NO LLM) ===
Bots retidos pelo Filtro L1 (se ativo): 19/20
Verdadeiros Positivos (VP): 10
Verdadeiros Negativos (VN): 19
Falsos Positivos (FP):      1
Falsos Negativos (FN):      0
Baseline Heuristico (>=3):  83.3% (25/30) [IC 95% Wilson: 66.4% - 92.7%]
Acuracia Gemini (IC 95%):   96.7% (29/30) [IC 95% Wilson: 83.3% - 99.4%]
Precisao:                   90.9%
Recall (Sensibilidade):     100.0%
F1-Score:                   95.2%
Resistencia Prompt Inject.: 6/6 (100.0%)
Tempo medio na API Gemini:  1.33s
```

---

## Notas Metodológicas e Rastreabilidade dos Dados (`resultados_validacao/`)

1. **Anonimização Pré-Execução (RFC 5737) e Ausência de Senhas no Prompt:** O script `triagem.py` não envia o campo `password` dos logs para a API externa. Além disso, para evitar a exposição de IPs residenciais dos autores, do host da infraestrutura ou de terceiros fora de listas públicas de ameaça, os endereços IP das sessões simuladas (`hum_01` a `hum_10`, incluindo `203.0.113.19` em `hum_07`), das 32 sessões inéditas que avançaram ao Nível 2 e do robô `bot_20_f91d83b42a11` (`198.51.100.200`) foram substituídos **antes** da chamada à API por faixas reservadas de documentação da **RFC 5737** (`192.0.2.0/24`, `198.51.100.0/24` e `203.0.113.0/24`). Assim, as saídas JSON salvas em `resultados_validacao/` correspondem exatamente ao texto retornado pela API.
2. **Estudo de Ablação (Prompt Neutro) e Teste de Generalização (10 Cenários Inéditos):** Como o prompt padrão de `triagem.py` inclui uma lista explícita de exemplos de comandos (`ls`, `cd`, `mkdir`, `ipconfig`, `wget`, `curl`), o arquivo `ablacao_prompt_neutro_30_sessoes_raw.json` registra a avaliação das mesmas 30 sessões com um prompt neutro (sem dicas de comandos), atingindo **100,0% (30/30)** e eliminando o falso positivo em `bot_20_f91d83b42a11`. Já o arquivo `generalizacao_10_cenarios_raw.json` avalia 10 cenários inéditos fora do vocabulário do prompt (ex.: humano usando `wget` para baixar `linpeas.sh`, `sudo su`, `ps aux`, `docker ps`, `curl ifconfig.me`; bot executando `cd /tmp && ls -la` em 0s ou `pkill -9 xmrig`), nos quais o prompt guiado atingiu **90,0% (9/10)** e o prompt neutro **100,0% (10/10)**.
3. **Auditoria Uniforme do MITRE ATT&CK (`conferencia_mitre`):** Cada sessão de `validacao_30_sessoes_raw.json` contém o objeto `conferencia_mitre` (`status` e `justificativa`). Aplicando o mesmo critério estrito às 3 sessões de teste de banner `echo xsec` (`bot_04` -> `T1595`, `bot_05` -> `T1592`, `bot_12` -> `T1082`) e às 2 sessões humanas de descoberta de privilégio (`hum_06` `find -perm -4000` -> `T1548.001` e `hum_07` `sudo -l` -> `T1548`), obtêm-se **25/30 (83,3%)** mapeamentos estritamente exatos e **5/30 (16,7%)** parciais.
4. **Auditoria dos Comandos de Mitigação (`auditoria_mitigacao`):** A validade sintática de **100,0% (30/30)** refere-se exclusivamente à regra primária `iptables -A INPUT -s <IP> -j DROP` (guiada pelo template do prompt e que requer adaptação manual para `DOCKER-USER` em contêineres Docker). Nos comandos secundários de host gerados livremente para as 10 sessões humanas, **5 de 10 sessões (50,0%)** apresentaram ressalvas operacionais (flag inexistente `passwd -a root` em `hum_04`, contas inferidas `admin_ti`/`sysadmin`/`backdoor` em `hum_06`/`hum_07`, e comandos destrutivos como `rm -f ~/.ssh/id_rsa`, `shred -u` ou `userdel -r` em `hum_04`, `hum_05`, `hum_06`, `hum_10` e `inj_03`), reforçando a obrigatoriedade de revisão humana.
