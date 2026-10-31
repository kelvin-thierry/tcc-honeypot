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
├── avaliar_metricas.py     # Script de validação com 30 sessões rotuladas (Matriz de Confusão)
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

[4/6] Sessao 350bf1bd00da | IP: 172.19.0.1 | Comandos: 7
   -> Classificacao: ATAQUE_HUMANO_DIRECIONADO (API Gemini - 2.98s)
   -> Risco: CRÍTICO | Resumo: Leitura de arquivos de senhas, busca de binarios SUID e persistencia SSH.
   -> MITRE ATT&CK: T1087 (Account Discovery), T1548.001 (Setuid and Setgid), T1098.004 (SSH Authorized Keys), T1070.003 (Clear Command History)
   -> Bloqueio: iptables -A INPUT -s 172.19.0.1 -j DROP
```
Ao final da execução, o relatório completo com todas as sessões analisadas é salvo no arquivo `relatorio_triagem.json`.

### 4. Reproduzir a Validação e a Matriz de Confusão (30 Sessões)
Para rodar o teste de validação com as 30 sessões rotuladas do TCC (20 bots e 10 ataques humanos simulados) e exibir a Matriz de Confusão, Acurácia, Precisão, Recall e F1-Score:
```bash
python3 avaliar_metricas.py
```

**Saída esperada da validação:**
```text
============================================================
RESULTADO DA VALIDACAO (MATRIZ DE CONFUSAO - N=30)
============================================================
Verdadeiros Positivos (VP - Humano acertado): 10
Verdadeiros Negativos (VN - Bot acertado):    19
Falsos Positivos      (FP - Bot -> Humano):   1
Falsos Negativos      (FN - Humano -> Bot):   0
------------------------------------------------------------
Acuracia Global: 96.7%
Precisao:        90.9%
Recall:          100.0%
F1-Score:        95.2%
Tempo Medio API: 1.89s por sessao
============================================================
```
