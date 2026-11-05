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

Este projeto integra o honeypot SSH **Cowrie** (rodando em contêiner Docker em ambiente de homelab sob conexão de banda larga residencial com redirecionamento NAT) a um script em Python que faz a triagem automática das sessões em três passos:

1. **Agrupamento de Sessão:** lê o arquivo `cowrie.json`, junta os eventos de uma mesma conexão pelo código da sessão (`session`), oculta o IP do servidor local e calcula o intervalo de tempo entre os comandos digitados.
2. **Filtro Local de Ruído (Nível 1):** descarta acessos sem comandos pós-login e verifica se o IP de origem já consta na lista pública **IPsum** (base diária de IPs conhecidos por varreduras automáticas) ou se executou apenas comandos repetitivos de robôs (ex.: `uname -s -v -n -r -m`). Essas sessões já são marcadas localmente como `BOT_AUTOMATIZADO` sem gastar requisições da API.
3. **Análise com IA (Nível 2):** envia as sessões interativas ou inéditas para a API do modelo **Google Gemini Flash** (`gemini-1.5-flash`), que classifica a sessão entre `BOT_AUTOMATIZADO` e `ATAQUE_HUMANO_DIRECIONADO`, associa os comandos às técnicas do **MITRE ATT&CK** e sugere comandos de bloqueio para firewall (`iptables`).

---

## Estrutura de Arquivos

```text
.
├── docker-compose.yml      # Configuração do contêiner Docker do Cowrie (porta 22 -> 2222)
├── etc/
│   ├── cowrie.cfg          # Configuração principal do honeypot (SSH ativo e saída em JSON)
│   └── userdb.txt          # Regra de autenticação do honeypot para observar ações pós-login
├── triagem.py              # Script principal: agrupamento, filtro IPsum, PROMPT_COM_REGRAS e PROMPT_NEUTRO
├── calcular_metricas.py    # Script independente (offline, sem API): imprime Matriz 2x2, IC 95%, McNemar e auditorias
├── avaliar_metricas.py     # Script de reprodução das 30 sessões, 2 baselines, ablações, generalização e auditorias
├── resultados_validacao/   # Saídas cruas da API, funil de 30 dias, auditoria MITRE v20 e mitigação (JSON/CSV)
│   ├── resumo_funil_30_dias.json                    # Contagens exatas dos 30 dias (1.381.038 eventos / 170.891 sessões)
│   ├── coleta_30_dias_32_sessoes_l2_raw.json        # Saída crua das 32 sessões reais que avançaram ao Nível 2 (31 VN, 1 FP)
│   ├── amostra_auditoria_nivel1_100_sessoes.json    # Auditoria manual (2 revisores) de 100 sessões retidas no Nível 1 (50 multi-cmd + 50 1-cmd)
│   ├── validacao_30_sessoes_raw.json                # 30 sessões (com pausas_segundos, 2 baselines, 2 execuções com +Ns, MITRE v20 e mitigação)
│   ├── auditoria_detalhada_30_sessoes.csv           # Planilha auditada técnica por técnica (MITRE ATT&CK v20) e comando por comando
│   ├── auditoria_detalhada_30_sessoes.json          # Versão JSON da planilha de auditoria detalhada das 30 sessões
│   ├── ablacao_prompt_neutro_30_sessoes_raw.json    # Ablação exploratória post-hoc nas 30 sessões com prompt neutro (com/sem +Ns)
│   ├── ablacao_sem_tempos_30_sessoes_raw.json       # Comparativo das 30 sessões com e sem as anotações de pausa (+Ns)
│   ├── generalizacao_10_cenarios_raw.json           # Teste de generalização em 10 cenários sintéticos (com e sem +Ns)
│   ├── adversarial_temporizacao_6_sessoes_raw.json  # Teste adversarial de tempo (3 humanos em rajada <=1s e 3 bots com sleep 5–7s)
│   └── prompt_injection_6_variantes_raw.json        # Saída crua das 6 variantes de Prompt Injection (6/6 não obedecidas)
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

### 4. Reproduzir a Validação e a Matriz de Confusão (30 Sessões + 2 Baselines + Auditoria MITRE v20)
Para calcular e imprimir no terminal todas as métricas da Seção 4.3 (Matriz de Confusão 2x2, Acurácia, IC 95% de Wilson, Precisão, Recall, F1-Score do LLM e dos dois baselines, teste exato de McNemar, cenário operacional Nível 2 e auditorias de MITRE ATT&CK v20 e mitigação) de forma 100% offline e sem necessidade de chaves:
```bash
python3 calcular_metricas.py
```
Também é possível utilizar o script de avaliação com a flag `--resumo`:
```bash
python3 avaliar_metricas.py --resumo
```
Ou para reexecutar todas as chamadas na API Gemini (requer `GEMINI_API_KEY`):
```bash
python3 avaliar_metricas.py
```

**Saída esperada da validação:**
```text
=== 1. MATRIZ DE CONFUSAO 2x2 (CONFIGURACAO PRINCIPAL N = 30 DIRETAS NO LLM) ===
VP = 10 | VN = 19 | FP = 1 | FN = 0
Cenario Operacional Nivel 2 (32 reais L2 + 10 humanas = 42): VP=10, VN=31, FP=1, FN=0 (Acuracia=97.6%, F1=95.2%)

=== 2. COMPARATIVO LLM vs. BASELINES HEURISTICOS (N = 30) ===
LLM (Regras +Ns)      : Acc=96.7% (29/30, IC95% 83.3%-99.4%) | P=90.9% | R=100.0% | F1=95.2%
Baseline 1 (>=3 cmds) : Acc=83.3% (25/30, IC95% 66.4%-92.7%) | P=69.2% | R=90.0% | F1=78.3% | McNemar p=0.125
Baseline 2 (Pausa >3s): Acc=96.7% (29/30, IC95% 83.3%-99.4%) | P=90.9% | R=100.0% | F1=95.2%

=== 3. AUDITORIA MITRE ATT&CK v20, MITIGACAO E TEMPO (N = 30) ===
Acerto estrito MITRE ATT&CK v20 : 23/30 (76.7%) exatos e 7/30 parciais
Regra primaria iptables + IP ok : 30/30 (100.0%)
Ressalvas em comandos de host   : 9/30 no total (8/10 humanos e 1/20 bots)
Tempo medio de resposta da API  : 1.33s (min=0.97s, max=3.03s, retentativas=0)
```

---

## Notas Metodológicas e Rastreabilidade dos Dados (`resultados_validacao/`)

1. **Anonimização Pré-Execução (RFC 5737) e Ausência de Senhas no Prompt:** O script `triagem.py` não envia o campo `password` dos logs para a API externa. Além disso, para evitar a exposição de IPs residenciais dos autores, do host da infraestrutura ou de terceiros fora de listas públicas de ameaça, os endereços IP das sessões simuladas (`hum_01` a `hum_10`, incluindo `203.0.113.19` em `hum_07`), das 32 sessões inéditas que avançaram ao Nível 2 e do robô `bot_20_f91d83b42a11` (`198.51.100.200`) foram substituídos **antes** da chamada à API por faixas reservadas de documentação da **RFC 5737** (`192.0.2.0/24`, `198.51.100.0/24` e `203.0.113.0/24`). Assim, as saídas JSON salvas em `resultados_validacao/` correspondem exatamente ao texto retornado pela API.
2. **Baseline de Temporização (`> 3 s`), Teste Adversarial de Tempo (`N = 6`), Ablação sem `(+Ns)` e Ablação Exploratória Post-hoc (`PROMPT_NEUTRO`):** O arquivo `validacao_30_sessoes_raw.json` publica os intervalos em segundos entre comandos (`pausas_segundos`) de todas as 30 sessões, além de duas execuções independentes da configuração principal (`resposta_crua_llm` e `resposta_crua_llm_com_tempos`, com 100% de concordância na classificação binária `29/30 = 96,7%`). Um baseline simples de temporização (`pausa máxima entre comandos > 3 s = humano`, avaliado post-hoc em `calcular_metricas.py`) atinge **96,7% (29/30, P=90,9%, R=100,0%, F1=95,2%)** nas 30 sessões (errando apenas na mesma sessão `bot_20_f91d83b42a11`, cujas pausas chegam a `4s`), enquanto o baseline de contagem (`>= 3 comandos distintos = humano`) obtém **83,3% (25/30, P=69,2%, R=90,0%, F1=78,3%; p = 0,125 no teste exato de McNemar)**. Já no teste adversarial de temporização (`adversarial_temporizacao_6_sessoes_raw.json`, com 3 humanos colando comandos em rajada `<= 1s` e 3 bots com `sleep` de `5–7s`), o baseline de pausa cai para **0/6 (0,0%)** e o de contagem faz **4/6 (66,7%)**, enquanto os prompts do LLM mantêm **6/6 (100,0%)**.
3. **Auditoria Uniforme do MITRE ATT&CK v20 (`conferencia_mitre` e `auditoria_detalhada_30_sessoes.csv`):** A conferência manual foi realizada por dois dos autores deste trabalho (Kelvin Miranda e Gabriel Saranço) sobre a versão **v20 (outubro de 2026)** do catálogo MITRE ATT&CK e registrada técnica por técnica em `auditoria_detalhada_30_sessoes.csv`. Aplicando o mesmo critério estrito a todas as 30 sessões — rebaixando a parcial as 3 sessões de teste de eco `echo xsec` (`bot_04` -> `T1595`, `bot_05` -> `T1592`, `bot_12` -> `T1082`), o comando de listagem `crontab -l` em `bot_20` (`T1053.003`), o comando `unset HISTFILE` em `hum_05` (`T1070.003` em vez de `T1562.003`/`T1690`, além da omissão de `T1059.004` para o shell reverso) e os comandos de busca `find -perm -4000` em `hum_06` (`T1548.001`) e `sudo -l` em `hum_07` (`T1548`) —, obtêm-se **23/30 (76,7%)** sessões integralmente exatas e **7/30 (23,3%)** parciais (ou **55/62 = 88,7%** ao nível individual das técnicas geradas).
4. **Auditoria Uniforme dos Comandos de Mitigação (`auditoria_mitigacao`):** Em **30/30 (100,0%)** das sessões, a regra primária `iptables -A INPUT -s <IP> -j DROP` teve sintaxe válida e o endereço IP exato da sessão (requerendo adaptação para a cadeia `DOCKER-USER` em ambientes com Docker NAT). Aplicando o critério uniforme de ressalvas aos comandos secundários de host em todas as 30 sessões (flags inválidas como `passwd -a`, bloqueio de conta administrativa `passwd -l root` ou contas inferidas `admin_ti`/`sysadmin`/`backdoor`, e remoção destrutiva de chaves/diretórios com `rm -f ~/.ssh/`, `shred -u` ou `userdel -r`), observaram-se ressalvas em **9 de 30 sessões (30,0%)**, sendo **8 de 10 sessões humanas (80,0%)** (`hum_03` a `hum_10`, das quais `6/10` envolvem comandos destrutivos, flags inválidas ou contas inferidas e `2/10` envolvem bloqueio de `root`) e **1 de 20 sessões de robôs (5,0%)** (`bot_20`, com `passwd -l root`).
