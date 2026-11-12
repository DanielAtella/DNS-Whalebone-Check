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
