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

### 2. Executar o script (Modo Interativo com os 3 Use Cases)
Basta rodar na pasta do projeto:
```bash
uv run dns_whalebone_check.py
```
> O `uv` criará o ambiente e instalará as dependências automaticamente em segundos. Em seguida, será exibido o menu interativo permitindo escolher entre o **Use Case 1**, **Use Case 2**, **Use Case 3** ou digitar os IPs manualmente.

### 3. Executar passando parâmetros direto via linha de comando (CLI)

- **Escolhendo um dos 3 Use Cases direto**:
  ```bash
  uv run dns_whalebone_check.py --use-case 1
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
```bash
pkg update && pkg install python rust libjpeg-turbo zlib
pip install -r requirements.txt
python3 dns_whalebone_check.py
```

---

## Personalizando os IPs padrão dos 3 Use Cases

No início do arquivo [`dns_whalebone_check.py`](file:///Users/daniel/Developer/DNS-Whalebone-Check/dns_whalebone_check.py#L51-L68), você encontra o dicionário `USE_CASES`, onde pode ajustar os nomes e os IPs pré-configurados de cada um dos 3 cenários.
