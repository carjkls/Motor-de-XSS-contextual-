# Motor de XSS contextual — design v1

Status: aprovado em conversa, aguardando revisão final antes do plano de implementação.

## Motivação / escopo

Ferramenta de teste de segurança (uso autorizado/pentest), na mesma linha do
`ssrf-scanner`: em vez de disparar uma lista fixa de payloads genéricos
(`<script>alert(1)</script>` em todo lugar), o motor **parseia a resposta
HTML/JS**, descobre **onde** e **em que contexto sintático** o valor
injetado é refletido, e gera um payload que fecha aquele contexto
especificamente, antes de confirmar execução de verdade num browser
headless.

**v1 cobre apenas XSS refletido.** DOM-based e stored ficam para iterações
futuras (ver "Fora de escopo" abaixo) — o projeto evolui incrementalmente a
partir daqui.

## Objetivos

- Descobrir parâmetros candidatos (query string, forms HTML, JSON body)
- Para cada um, localizar onde o valor reflete na resposta e classificar o
  contexto sintático (texto HTML, atributo, URL de atributo, comentário
  HTML, string JS, template literal JS)
- Gerar um payload sintaticamente válido para aquele contexto específico
- Confirmar execução real via browser headless (não apenas inferência
  estática)
- Reportar achados com veredito diferenciado: `confirmed` (execução
  provada) vs `likely` (contexto bateu, mas sem confirmação de execução)

## Fora de escopo (v1)

- XSS DOM-based (sinks client-side tipo `innerHTML`) e stored (fluxo de
  duas etapas) — ficam para depois
- Contexto CSS — não executa JS em browsers modernos, não se encaixa no
  modelo de confirmação por marcador
- Bypass de encoders/WAFs específicos — fica para uma iteração futura, uma
  vez que o pipeline básico estiver rodando

## Arquitetura

Pipeline: **discovery → triagem estática (localiza o reflexo) →
classificação de contexto → geração de payload por contexto → confirmação
via browser (marcador global) → relatório.**

A fase estática não decide exploitabilidade — só localiza *onde* e *como*
o valor foi refletido. Quem decide se é exploitável de verdade é o browser
executando o payload real.

### Componentes

1. **`core/discovery.py`** — adaptado do `ssrf-scanner`: candidatos via
   query string, forms HTML, JSON body (por JSON-path). Lógica reaproveitada
   sem mudança de fundo.

2. **`core/http_client.py`** — wrapper async `httpx` do `ssrf-scanner`,
   reaproveitado para a fase estática (triagem rápida, concorrência
   limitada).

3. **`core/context.py`** (novo) — para cada candidato: injeta um token
   simples (sem caracteres especiais — só para *localizar*, não para
   explorar), refaz o fetch, parseia com BeautifulSoup e localiza toda
   ocorrência do token na árvore. Classifica cada ocorrência em um
   `ReflectionContext`:
   - `html_text` — texto solto
   - `html_attribute` — dentro de um valor de atributo (guarda qual
     atributo e qual aspas)
   - `url_attribute` — especificamente `href`/`src`
   - `html_comment` — dentro de `<!-- -->`
   - `js_string` / `js_template_literal` — dentro de `<script>`, usando um
     scanner leve por máquina de estados (regex) que rastreia aspas/crases
     abertas até a posição do token

   `shortcut: o scanner de JS não é um parser/AST completo — não lida bem
   com JS minificado ou edge cases exóticos de ASI (automatic semicolon
   insertion). Se isso se mostrar um problema real em alvos reais, trocar
   por um tokenizer JS de verdade (ex. pyjsparser) numa iteração futura.`

4. **`payloads/context_payloads.py`** (novo) — dado um `ReflectionContext`,
   gera o payload que fecha a sintaxe daquele contexto e seta
   `window.__xss_<token>__=1`:
   - `html_text` → `<script>window.__xss_TOKEN__=1</script>`
   - `html_attribute` → fecha a aspa certa + handler que dispara sozinho:
     `" autofocus onfocus="window.__xss_TOKEN__=1`
   - `js_string` → fecha a string com a aspa certa, executa, comenta o
     resto da linha: `';window.__xss_TOKEN__=1;//`
   - `js_template_literal` → `${(window.__xss_TOKEN__=1,'')}`
   - `url_attribute` (`href`) → `javascript:window.__xss_TOKEN__=1` — exige
     clique do usuário; não confirmável sozinho no headless, fica marcado
     `likely` por padrão.

5. **`core/browser_confirm.py`** (novo, Playwright) — recebe a URL (GET) ou
   o corpo HTML já com o payload (POST — via `page.set_content()`, já que
   `page.goto()` só navega por GET), carrega, espera um grace period curto
   (para handlers tipo `onfocus` dispararem) e lê
   `window.__xss_<token>__` via `page.evaluate()`. Um browser context novo
   por verificação (isolamento), instância de browser reaproveitada entre
   verificações (performance).

6. **`reporting/report.py` + `cli.py`** — mesmo padrão do `ssrf-scanner`
   (console colorido + JSON, `xsscan` como entrypoint). Flag `--no-browser`
   roda só a fase estática quando Playwright não está disponível (relata
   `likely`, nunca `confirmed`).

## Fluxo de dados

1. Baseline (GET ou POST conforme config, mesma lógica do `ssrf-scanner`)
2. `discover_candidates()` → lista de parâmetros candidatos
3. Para cada candidato: injeta o token simples, refaz a requisição, roda
   `context.py` sobre a resposta → lista de `ReflectionContext` (ocorrências
   idênticas no mesmo tipo de contexto são deduplicadas — testa só uma)
4. Para cada contexto distinto: gera o payload específico (token novo e
   único por payload)
5. Reinjeta: GET → monta a URL e manda para `browser_confirm.py` via
   `page.goto()`; POST/JSON → faz a requisição com `http_client.py`, pega o
   corpo da resposta e manda para o browser via `page.set_content()`
6. Browser carrega, espera o grace period curto, lê o marcador
7. Monta `Finding`: `confirmed` (marcador disparou), `likely` (contexto
   bateu, mas sem confirmação — CSP, validação adicional, ou contexto que
   exige clique), `info` (reflete mas contexto não é claramente
   explorável)
8. Dedupe + sort por severidade (mesmo padrão do `detector.py`/`dedupe()`
   do `ssrf-scanner`) → relatório

## Tratamento de erro

- HTML malformado: BeautifulSoup é tolerante, segue em frente
- JS minificado/ambíguo: classifica como `unknown`, pula geração de
  payload para aquele ponto sem travar o scan
- Playwright ausente ou falha ao subir: erro claro + sugestão explícita de
  `--no-browser`
- CSP bloqueando execução: marcador não dispara mesmo com payload bem
  posicionado → cai em `likely`, evidência menciona possível CSP
- Timeout de navegação/espera: mesmo padrão de `timeout`/config do
  `ssrf-scanner`; vira parte do resultado, não derruba o scan

## Testes

- `context.py` / `context_payloads.py`: testes unitários puros (sem
  rede/browser) — HTML/JS de exemplo com o token em cada posição →
  contexto esperado; contexto → payload esperado (aspas fechando
  corretamente)
- `lab/`: app Flask com uma rota por contexto (texto, atributo, string JS,
  template literal), refletindo sem escapar — mesmo padrão já estabelecido
  no `ssrf-scanner`, serve de alvo real para testar o pipeline inteiro
  ponta a ponta com o browser incluso

## Estrutura de repositório

Repo novo e independente (`xss-contextual-scanner`), adaptando os módulos
de discovery/http client do `ssrf-scanner` — sem extrair lib compartilhada
nesta fase.

## Decisões registradas (histórico da conversa)

| Decisão | Opção escolhida |
|---|---|
| Escopo v1 | Apenas refletido |
| Detecção de contexto | Estático (triagem rápida) + browser real só para candidatos (abordagem C/híbrida) |
| Confirmação de execução | Marcador global (`window.__xss_<token>__`), não hook de `alert`/`dialog` |
| Estrutura de repo | Novo e independente, módulos adaptados do ssrf-scanner |

## Próximos passos / trabalho futuro (fora da v1)

- XSS DOM-based (sinks client-side)
- XSS stored (fluxo de duas etapas)
- Upgrade do scanner de JS para um tokenizer real se o regex-based se
  mostrar frágil
- Bypass de encoders/WAFs
