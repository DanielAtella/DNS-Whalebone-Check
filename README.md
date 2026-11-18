# DNS Whalebone Check (Python + `uv`)

Ferramenta multiplataforma (**Windows**, **macOS**, **Linux** e **Android via Termux ou ADB**) para validar o bloqueio de domínios por servidores DNS (Whalebone / NOS), sem necessidade de permissões de administrador (`root`/`sudo`) ou alteração das configurações de rede do sistema operacional.

## O que a ferramenta valida?

Para cada **Servidor DNS** e para cada **URL** da lista:
1. **Resolução DNS isolada (`dnspython`)**: consulta diretamente o IP do servidor DNS em teste (`@DNS_IP`), coletando os IPs resolvidos e o tempo de resposta em `ms`.
2. **Handshake TLS (`TLSv1.3` com fallback para `TLSv1.2`)**: conecta diretamente ao IP retornado pelo DNS na porta `443` enviando o `SNI` do domínio, extraindo versão TLS, Cipher, código/texto de verificação do certificado, `Common Name (CN)`, data de expiração e salvando o dump completo com o certificado PEM em `tls_logs/`.
3. **Sondagem HTTP/HTTPS isolada**: realiza a requisição conectando diretamente ao IP retornado pelo DNS em teste, capturando status HTTP, tempo em `ms`, status do certificado SSL e URL de redirecionamento (ex: redirect para página de bloqueio).
4. **Screenshot com Banner Informativo (`Pillow` + Browser / ADB / Card Visual)**:
   - **Desktop (Windows / macOS / Linux)**: usa automaticamente o Google Chrome, Microsoft Edge, Brave ou Chromium instalado em modo headless com `--host-resolver-rules`, forçando o navegador a usar o IP retornado pelo DNS testado sem mexer no DNS do sistema operacional.
   - **Android via ADB (`--mode adb`)**: abre a URL no navegador do celular Android conectado via USB e captura a tela real do aparelho (`adb exec-out screencap -p`).
   - **Android via Termux (`--mode headless-card` ou automático)**: gera um cartão visual de evidência completo com todos os dados técnicos e prévia da página/bloqueio.
   - No topo de todas as imagens é adicionado o **banner colorido** (Verde = `2xx` + SSL OK, Amarelo = `3xx` Redirect, Vermelho = Bloqueado / Erro SSL / Erro HTTP) com as 5 linhas de resumo.

---

## Como executar facilmente com `uv`

### 1. Instalar o `uv` (caso ainda não tenha)
- **macOS / Linux**:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- **Windows (PowerShell)**:
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```

### 2. Executar o script (Modo Interativo com os 3 Use Cases + Arquivamento e SCP)
Basta rodar na pasta do projeto:
```bash
uv run dns_whalebone_check.py
```
> O `uv` criará o ambiente e instalará as dependências automaticamente em segundos. Em seguida, será exibido o menu inicial permitindo:
> - Escolher entre o **Use Case 1**, **Use Case 2**, **Use Case 3**, digitar os IPs manualmente ou **arquivar/enviar um resultado já existente** (`[5]`);
> - Escolher se deseja compactar o resultado em **TAR (`.tar.gz`)** ou **ZIP (`.zip`)**;
> - Enviar o resultado para um **servidor remoto via SCP**, informando o host/IP, porta, caminho remoto, usuário e **senha oculta de forma segura** (`getpass`, sem exibir no terminal e sem gravar em logs ou histórico de comandos).

### 3. Executar passando parâmetros direto via linha de comando (CLI)

- **Escolhendo um dos 3 Use Cases direto**:
  ```bash
  uv run dns_whalebone_check.py --use-case 1
  ```
- **Compactando em TAR ou ZIP e enviando via SCP para um servidor remoto**:
  ```bash
  uv run dns_whalebone_check.py --use-case 1 --archive tar --scp-host 192.168.1.50 --scp-user admin --scp-path /tmp
  ```
- **Informando os servidores DNS diretamente**:
  ```bash
  uv run dns_whalebone_check.py --dns 10.36.41.115 8.8.8.8
  ```
- **Forçando captura de um celular Android conectado via ADB**:
  ```bash
  uv run dns_whalebone_check.py --use-case 1 --mode adb
  ```

---

## Execução com Python tradicional (`pip` + `requirements.txt`)

Caso alguém prefira usar `pip` padrão ou esteja no **Android (Termux)**:

```bash
python3 -m venv .venv
# No Windows: .venv\Scripts\activate
# No macOS/Linux/Termux:
source .venv/bin/activate

pip install -r requirements.txt
python3 dns_whalebone_check.py
```

### Dica para Android (Termux direto no aparelho)
No aplicativo **Termux** no Android:

1. **Instalar pacotes básicos (rápido — renderiza o View da página de bloqueio via HTML + Inspector)**:
   ```bash
   pkg update && pkg install -y python python-pillow openssl
   pip install dnspython
   python3 dns_whalebone_check.py --output-dir ~/storage/downloads/resultado_dns
   ```

2. **(Opcional) Instalar o navegador Chromium real dentro do Termux** (caso queira que o próprio Chromium renderize o CSS/imagens da página de bloqueio em modo `--headless`):
   ```bash
   pkg install -y x11-repo tur-repo
   pkg install -y chromium
   python3 dns_whalebone_check.py --output-dir ~/storage/downloads/resultado_dns
   ```

---

## Configuração via arquivo `.env`

A ferramenta lê automaticamente o arquivo [`.env`](file:///Users/daniel/Developer/DNS-Whalebone-Check/.env) (ou [`.env.example`](file:///Users/daniel/Developer/DNS-Whalebone-Check/.env.example)) na pasta do projeto, permitindo pré-configurar:

- **`DNS_SERVERS`**: Lista de servidores DNS utilizados (ex: `10.36.41.114, 8.8.8.8`).
- **`DOMAINS`**: Lista de domínios ou URLs a serem testados (separados por vírgula ou espaço).
- **`ARCHIVE_FORMAT`**: Formato de compactação ao terminar (`tar`, `zip` ou `none`).
- **`SCP_ENABLED`**: Transferir automaticamente ao terminar via SCP (`true` ou `false`).
- **`SCP_HOST` / `SCP_PORT` / `SCP_USER` / `SCP_PATH`**: IP/Hostname, porta, usuário e diretório de destino no servidor remoto.
- **`AUTO_RUN`**: Se `true` (ou passando `--from-env` na CLI), executa direto com as configurações do `.env` sem abrir o menu interativo (solicitando apenas a senha oculta via `getpass` caso `SCP_PASSWORD` não esteja definido).

## Personalizando os IPs padrão dos 3 Use Cases

No arquivo [`.env`](file:///Users/daniel/Developer/DNS-Whalebone-Check/.env) (`USE_CASE_1_DNS`, `USE_CASE_2_DNS`, `USE_CASE_3_DNS`) ou no início de [`dns_whalebone_check.py`](file:///Users/daniel/Developer/DNS-Whalebone-Check/dns_whalebone_check.py#L68-L84), você encontra o dicionário `USE_CASES`, onde pode ajustar os nomes e os IPs pré-configurados de cada um dos 3 cenários.

---

## Automação Android Local (Termux ou ADB): `android_whalebone_check.py`

Para auditoria direta em um aparelho Android (via USB ADB ou nativamente no Termux):

```bash
cp .env.android.example .env.android
python3 android_whalebone_check.py
```

Principais validações executadas:
- Auditoria de **Private DNS** (Android OS) e **Secure DNS / DoH** (Google Chrome), calculando o risco de bypass.
- Navegação nos aplicativos configurados (`reddit`, `instagram`, `netflix`, etc.) e nas URLs de teste no Google Chrome.
- Geração de `report.json`, `report.csv`, `run.log`, `ui_dumps/` e `screenshots/` com banner informativo.

---

## Automação no Kobiton: `kobiton_whalebone_check.py`

O script [`kobiton_whalebone_check.py`](file:///Users/daniel/Developer/DNS-Whalebone-Check/kobiton_whalebone_check.py) executa todas as validações diretamente nos dispositivos Android no **Kobiton** (via Appium W3C WebDriver, sem dependências externas obrigatórias), sem usar a rede ou alterar o DNS do host onde o script é executado.

### 1. Configuração (`.env.kobiton`)

```bash
cp .env.kobiton.example .env.kobiton
```

Principais variáveis em [`.env.kobiton.example`](file:///Users/daniel/Developer/DNS-Whalebone-Check/.env.kobiton.example):
- **`KOBITON_USERNAME` / `KOBITON_API_KEY`**: Credenciais de acesso ao Kobiton.
- **`KOBITON_UDID` / `KOBITON_UDIDS`**: Um ou mais UDIDs separados por vírgula (ex: `R3CRA0RKYXN,129b5649`).
- **`KOBITON_TARGET_MSISDN`**: MSISDN (ou ICCID) do SIM que deve ficar ativo durante os testes.
- **`KOBITON_DNS_SERVERS`**: Servidores DNS destino para teste de conectividade a partir do dispositivo (ex: `10.36.41.115`).
- **`KOBITON_BLOCK_IPS`**: IPs de resposta DNS que confirmam bloqueio Whalebone/NOS (padrão: `212.113.177.247`).
- **`KOBITON_DISABLE_WIFI_DURING_TESTS`**: Desativa o Wi-Fi no Android durante os testes para forçar uso da rede móvel e restaura ao final (padrão: `true`).

### 2. Listar dispositivos e MSISDNs disponíveis no Kobiton

```bash
# Lista rápida via API REST do Kobiton
python3 kobiton_whalebone_check.py --list-devices

# (Opcional) Consulta os MSISDNs diretamente nos dispositivos online e livres
python3 kobiton_whalebone_check.py --list-devices --probe-msisdn
```

### 3. Executar os testes no Kobiton

```bash
# Usando as configurações de .env.kobiton
python3 kobiton_whalebone_check.py

# Ou informando dispositivos e DNS via linha de comando
python3 kobiton_whalebone_check.py --udids R3CRA0RKYXN 129b5649 --dns-servers 10.36.41.115 --target-msisdn +351930992785
```

### Fluxo executado em cada dispositivo
1. **Wi-Fi**: detecta o estado inicial e desativa o Wi-Fi no Android durante os testes (restaurado ao final).
2. **Dual SIM & MSISDN**: lê o estado inicial de `SIM1` e `SIM2`, identifica os MSISDNs (via `dumpsys`, `siminfo`, `iphonesubinfo` e UI do Gestor SIM, descartando valores mascarados como `+3519[****`), ativa o SIM alvo e desativa o outro.
3. **Ciclo de Modo Avião**: ativa por `4s` e desativa aguardando `10s` para forçar o deregistro e novo registro do SIM na rede móvel.
4. **Confirmação de APN + Internet**: verifica nos marcos `5s, 15s, 45s, 2m, 5m` se o SIM registrou na APN (com IPv4/IPv6 e DNS) e navega na internet. Se não registrar em até `5m`, aborta, restaura o estado original e reporta o erro.
5. **Telemetria móvel & Limpeza de cache**: coleta operadora, MCC/MNC, tipo de rede, roaming, APN, interface, IPv4, IPv6 e DNS recebidos da APN; limpa o cache do Chrome e testa a conectividade do DNS destino a partir do dispositivo.
6. **Private DNS, Apps e Chrome**:
   - Dispensa diálogos modais (ex.: *"Desbloqueie as suas palavras-passe... Agora não"* no Netflix).
   - Para cada URL no Chrome, aguarda até `2m` nos marcos `5s, 15s, 30s, 1m, 2m`.
   - Em erros de certificado/segurança, tira o print do erro, clica em **Avançadas -> Avançar para o site**, aguarda o carregamento e tira um novo print confirmando a página de bloqueio.
   - Fecha cada aba aberta e encerra o Chrome ao final.
7. **Restauração e Evidências**: no bloco `finally` (mesmo em `KeyboardInterrupt` ou erro), restaura SIM1/SIM2, Modo Avião, DNS e Wi-Fi ao estado original, encerra a sessão no Kobiton, organiza os prints em `screenshots/<MSISDN>/` e gera `report.json` (incluindo `telemetry.cellular_apn` e `telemetry.waterfalls`) e `report.csv`.

---

## Testes Unitários

Para executar a suíte de testes unitários localmente:

```bash
python3 -m unittest tests/test_kobiton_whalebone_check.py tests/test_android_whalebone_check.py -v
```
