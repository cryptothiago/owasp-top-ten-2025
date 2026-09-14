# OWASP Top 10:2025 — Vulnerable Training Lab

Aplicação web intencionalmente vulnerável para estudar **exploração controlada, causa raiz e correção** das categorias do OWASP Top 10:2025.

> ⚠️ **Nunca publique este projeto na Internet.**
> Ele contém vulnerabilidades reais de treinamento. Execute somente em localhost, VM, container ou rede de laboratório isolada.

## Categorias

| ID | Categoria | Exercício |
|---|---|---|
| A01 | Broken Access Control | IDOR em notas |
| A02 | Security Misconfiguration | endpoint de diagnóstico exposto |
| A03 | Software Supply Chain Failures | confiança em pacote sem origem/hash |
| A04 | Cryptographic Failures | senha em claro + Base64 |
| A05 | Injection | SQL Injection |
| A06 | Insecure Design | cupom de uso único reutilizável |
| A07 | Authentication Failures | autenticação fraca e sem rate limit |
| A08 | Software or Data Integrity Failures | estado de perfil adulterável |
| A09 | Security Logging & Alerting Failures | ação sensível sem auditoria |
| A10 | Mishandling of Exceptional Conditions | stack trace exposto |

## Subir com Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Abra:

```text
http://127.0.0.1:5000
```

## Subir com Docker

```bash
docker compose up --build
```

O `docker-compose.yml` publica explicitamente somente em:

```text
127.0.0.1:5000
```

## Credenciais de laboratório

```text
alice / alice123
bob   / bob123
admin / admin123
```

São **credenciais fictícias**, criadas apenas dentro do banco SQLite local.

## Como estudar cada falha

1. Abra o card da categoria.
2. Execute a versão **Vulnerável**.
3. Observe o resultado.
4. Execute a versão **Corrigida** com a mesma entrada.
5. Abra `app.py` e compare os dois handlers.
6. Explique com suas próprias palavras:
   - qual era a fronteira de confiança;
   - qual propriedade de segurança foi violada;
   - por que a correção funciona;
   - o que ainda seria necessário em produção.

## Exemplos rápidos

### A01 — IDOR

Entre como `alice` e compare:

```text
/vuln/notes/1
/vuln/notes/2
```

A implementação vulnerável valida apenas se a nota existe. A corrigida inclui `owner_id` na decisão de autorização.

### A05 — SQL Injection

Na busca vulnerável:

```text
' OR '1'='1' --
```

Depois repita exatamente a mesma entrada na busca corrigida. A diferença está entre **concatenação de SQL** e **query parametrizada**.

### A08 — Integridade

A versão vulnerável usa Base64 para representar:

```json
{"username":"alice","role":"admin"}
```

Base64 não fornece integridade. A versão corrigida demonstra assinatura HMAC; em sistemas reais, autorização não deve confiar apenas em atributos controlados pelo cliente.

## Observações de segurança

Este projeto evita deliberadamente:
- execução de comandos do sistema;
- download/instalação real de pacote malicioso;
- SSRF contra serviços externos;
- credenciais reais;
- exposição intencional em `0.0.0.0` fora do Docker local.

Mesmo assim, **é uma aplicação vulnerável**. Trate-a como laboratório.

## Estrutura

```text
.
├── app.py
├── storage.py
├── templates/
├── static/
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Reset

Na tela inicial existe um botão **Resetar banco**, que recria os dados de demonstração.

## Sugestões de evolução

- adicionar testes automatizados que provem a vulnerabilidade e a correção;
- criar desafios sem mostrar a solução;
- adicionar pontuação/flags;
- integrar ZAP em modo passivo;
- criar uma branch `vulnerable` e outra `fixed`;
- mapear cada exercício para CWE e OWASP ASVS;
- adicionar uma API REST vulnerável além da interface web.

## Uso

Somente para treinamento, estudo, CTF/lab e validação defensiva em ambiente autorizado.
