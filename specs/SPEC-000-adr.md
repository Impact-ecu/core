# SPEC-000 · ADR do Impact (plataforma de verificação e recalibração de ECU)

Fonte canônica desta rodada: artefato HTML do ADR no Claude, versão 12 (2026-10-18). Este markdown é a cópia versionada no repositório; os diagramas estão só no artefato.

Nome do produto: **Impact**. Organização GitHub: `Impact-ecu`. Este repositório é o `core` público (AGPL-3.0); corpus e plugins de família ficam em repositórios privados da organização.

Decisões fixadas pelo autor (Luiz, 2026-10-18): confiabilidade é o produto; o núcleo crítico (kernel de binário, plugins por família, gate de verificação, proveniência) é construído primeiro e muito bem feito, antes de qualquer venda; custo zero no MVP (tudo grátis ou open source, em regime de teste); o projeto é só software, sem hardware próprio, com oráculo delegado à oficina parceira; negócio e jurídico entram só na Fase 1.

---

ADR-000 · Documento de arquitetura

# Plataforma de Recalibração de ECU

2026-10-18 · Luiz · versão 12 · custo zero no MVP fixado como princípio; comparativo com líderes por tópico

## Visão e escopo

Uma plataforma SaaS que recebe o dump de uma ECU/TCU, identifica a família do controlador, localiza as tabelas de calibração, deixa o tuner editá-las com segurança e devolve um binário com checksum válido. O MVP é só software: a leitura e gravação física ficam nos equipamentos que a oficina já tem (KESS3, Flex, Autotuner), e a plataforma consome o arquivo que eles exportam.

### Dentro do escopo

- Ingestão de dumps (full read, partial read, bancada) e identificação automática de ECU/TCU.
- Detecção de mapas por heurística e por definições importadas, com visualização 2D/3D e edição.
- Diff entre versões, histórico, rollback e comparação com o arquivo original.
- Recálculo de checksum por família de ECU (plugin).
- Biblioteca de definições (equivalente a XDF/A2L/map pack) versionada e compartilhável entre tenants.
- Multi-tenant: oficina master, sub-dealers, créditos por arquivo.

### Fora do escopo (decisão, não limitação)

- Qualquer função de remoção ou desativação de controle de emissão: DPF, EGR, SCR/AdBlue, catalisador, lambda, DTC de emissão. Não existe no produto, nem como flag oculta.
- Driver de comunicação com a ECU (OBD/bench/boot) no MVP. Entra numa fase posterior como integração com hardware de terceiros, não como hardware próprio.
- Garantia de ganho de potência: a plataforma entrega ferramenta e dado, não arquivo pronto.

### Público-alvo

1.  Oficinas de remap que hoje pagam WinOLS, ECM Titanium ou StageX e querem fluxo mais rápido em carros do mercado brasileiro.
2.  Tuners independentes que trabalham com Speeduino/FuelTech/MegaSquirt e querem o mesmo editor para ECU original.
3.  Fase 2: fabricantes de hardware de leitura que queiram embarcar o editor como white-label.

## Princípios

Agnosticidade é o princípio número um: o core não sabe de que fabricante é a ECU, de que ferramenta veio o arquivo, nem em que nuvem roda. Tudo que é específico vive atrás de uma interface, e a interface é o produto.

| Eixo                        | O core conhece                                           | Fica atrás de interface                                                                  | Como se garante                                                                                              |
|-----------------------------|----------------------------------------------------------|------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Fabricante e família de ECU | Um binário, um layout de memória, uma lista de mapas     | Assinaturas, checksums, offsets, endianness, regiões protegidas                          | `EcuPlugin`; nenhum `if family ==` fora do plugin; teste de contrato roda igual para toda família            |
| Ferramenta de leitura       | Bytes + hash + origem declarada                          | Formato de container (KESS, Flex, Autotuner, CMD, bdm), cabeçalhos, criptografia do dump | Adaptadores de ingestão que normalizam para `.bin` cru; o pipeline nunca vê o container                      |
| Formato de definição        | Modelo interno `MapDef`                                  | XDF, A2L, DAMOS, CSV, formato de map pack de terceiros                                   | Conversores de borda em ambas as direções; round-trip test (importa, exporta, compara)                       |
| Nuvem e infra               | Fila, object store, banco, segredos, como abstrações     | S3 vs GCS vs MinIO, NATS vs SQS, Vault vs KMS                                            | Interfaces finas por recurso (não um framework); MinIO + NATS + Postgres rodam em `docker compose` no laptop |
| Cliente                     | API REST + SSE                                           | Web, desktop, CLI, integração embarcada em hardware de terceiros                         | Nenhuma lógica de domínio no front; o editor é um consumidor da API como qualquer outro                      |
| Motor de detecção           | Interface `Detector.detect(blob, layout) -> [Candidate]` | Heurística, definições, ML                                                               | Detectores são plugáveis e combináveis por score; trocar um não muda a API                                   |

Os outros princípios derivam desse: **imutabilidade** (original nunca muda, tudo é patch), **determinismo** (mesma entrada, mesmo hash), **verificação antes de confiança** (nada é exportado sem verify verde) e **o usuário ensina o sistema** (toda correção vira dado).

**Restrição fixa do MVP: custo zero.** Tudo gratuito ou open source, e tudo ainda em regime de teste, sem produto vendável. Isso não afrouxa um byte da arquitetura: o rigor do núcleo é exigência de confiabilidade e independe de dinheiro. O que muda é o que fica fora até a Fase 1: licença de ferramenta de mercado como segundo oráculo, simuladores pagos, qualquer SaaS pago, hardware. O oráculo `golden_concordant` no MVP vem só do que a oficina já tem mais implementações open source (TunerPro, RomRaider, descrições públicas de checksum); variante sem concordância gratuita fica `unknown_variant` e não entra. Qualquer melhoria do comparativo que custe dinheiro é Fase 1 ou posterior, por definição.

## Cobertura de mercado

O leque é mercado nacional primeiro, importados em seguida; a arquitetura é a mesma, o que muda é o custo de cada plugin. Os importados premium trazem duas coisas boas: tíquete alto por arquivo e ECUs bem documentadas pela comunidade; e uma ruim: mais proteção (assinatura, boot criptografado) nos anos recentes.

| Segmento                  | Marcas e motores típicos                                                                               | ECUs principais                                                                                                                                                                                                          | Proteção típica                                                                                                                                                                               | Prioridade          |
|---------------------------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| Nacional popular          | Fiat Fire Evo/T-Jet/Firefly, VW TSI 1.0/1.4, GM 1.0/1.4 e 1.0/1.2 turbo, Renault 1.0/1.6 SCe e 1.3 TCe | Marelli IAW 7GF/9GF (Fire), IAW 8GMF (T-Jet), Firefly a verificar (provável 10GF); Bosch MED17.5.21/.25 e MG1CS002 (VW); ACDelco E83/E80/E78 (GM; turbo a verificar); Continental EMS31xx (Renault SCe; TCe a verificar) | Baixa a média; muita leitura por OBD ainda possível                                                                                                                                           | Fase 0 e 1          |
| Nacional picapes e diesel | Toro/Ranger/Hilux/S10/Amarok 2.0 a 3.2                                                                 | Bosch EDC17C59/C69/CP20, Continental SID209 (Ranger 2.2/3.2), Denso (Hilux)                                                                                                                                              | Média; checksums mais complexos                                                                                                                                                               | Fase 1              |
| Importado alemão premium  | BMW B48/B58/N55, Audi/VW EA888 e EA839, Mercedes M264/M256, Porsche 9A2                                | Bosch MG1/MD1, MEVD17, Siemens/Continental SIM2xx, Bosch MED40 (Mercedes)                                                                                                                                                | Alta: assinatura RSA e boot criptografado nas gerações recentes (SA2 é procedimento de desbloqueio VAG, não proteção da ECU); depende de bench/boot e de exploits dos fabricantes de hardware | Fase 2              |
| Importado asiático        | Hyundai/Kia Smartstream e TGDi, Toyota, Honda                                                          | Kefico CPEGD2.x (base MG1), Continental SIM2K-24x (Kappa antigos), Denso, Keihin                                                                                                                                         | Média a alta; Toyota e Honda com pouca comunidade                                                                                                                                             | Fase 2, sob demanda |
| TCUs                      | VW DQ200/DQ250/DQ381, ZF 8HP (BMW, Audi, Jeep), Mercedes 9G-Tronic                                     | Temic/Continental, ZF, Bosch                                                                                                                                                                                             | Média; checksums próprios                                                                                                                                                                     | Fase 2              |

Regra de entrada de uma família no catálogo: só entra com corpus mínimo de 20 dumps distintos, golden files de checksum verificados e um tuner de referência que valide a definição inicial. Sem isso, a família fica em *beta* atrás de feature flag.

## Pontos críticos e primeiros ganhos

Esta seção diz onde o projeto quebra e onde a estrutura precisa existir desde o primeiro commit; o resto pode ser improvisado e refeito. A regra: investir cedo onde errar é irreversível ou custa carro de cliente; improvisar onde errar custa uma refatoração.

| Ponto crítico                     | Por que é crítico                                                                              | Estrutura desde o início                                                                                | Pode esperar                              |
|-----------------------------------|------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------------------------------|
| Checksum por família              | Erro trava o carro; é o único defeito que o cliente não perdoa                                 | Golden files, verify obrigatório antes e depois do export, plugin versionado, teste de contrato         | Cobertura de muitas famílias              |
| Identificação da ECU              | Identificação errada aplica layout errado e libera patch em região proibida                    | Confiança explícita, fallback manual sempre disponível, região protegida como padrão quando em dúvida   | Precisão alta na identificação automática |
| Modelo de patches e imutabilidade | Mudar isso depois exige migrar todos os projetos de todos os clientes                          | `Artifact`, `Patch`, `Version` e `Event` como estão no modelo, com testes de propriedade (determinismo) | Interface bonita de histórico             |
| Interface do plugin de ECU        | É o contrato que a comunidade e os parceiros vão programar contra; quebrar depois custa adoção | Protocolo estável, versionado, com suíte de conformidade                                                | Plugins além da primeira família          |
| Corpus de dumps rotulados         | Sem corpus não há teste, não há detecção, não há ML; é o ativo que ninguém consegue copiar     | Acordo com oficinas piloto, pipeline de anonimização e consentimento desde o dia 1                      | Volume grande                             |
| Isolamento por tenant             | Vazamento cruzado de binário encerra o negócio                                                 | RLS, prefixo de bucket, chave por tenant, no esquema inicial                                            | SSO, sub-dealers, billing fino            |
| Decisão sobre emissões            | Não dá pra "adicionar depois" uma proibição que o produto já violou                            | Regiões protegidas no layout e termos de uso desde o MVP                                                | Certificações formais                     |
| Editor 2D/3D                      | É onde o tuner passa o dia; mas é só front e pode ser refeito                                  | Nada além de consumir a API                                                                             | WebGL, offline, desktop                   |
| Multi-cloud e Kubernetes completo | Importante na v1, irrelevante com 5 clientes                                                   | Interfaces finas para fila, storage e segredos                                                          | Mesh, Karpenter, multi-região             |

### Fase −1: descoberta (duas semanas, sem código do núcleo)

As três perguntas da seção Revisão não têm resposta hoje, e isso define a primeira fase: descobrir, não construir. Nenhuma linha do kernel antes do critério de saída abaixo.

1.  **Uma tarde na oficina parceira, acompanhando um serviço inteiro.** Ferramenta usada, o que sai dela (extensão, container, precisa da nuvem do fabricante?), se edita ou compra arquivo pronto, quanto tempo o carro fica parado. Vira a primeira linha da tabela de ferramentas.
2.  **Acordo de oráculo com a oficina.** Este projeto é software; nenhum ferro na sua mesa. A oficina lê e grava com o Flex dela, no carro ou na ECU dela, e devolve dados: hash do arquivo gravado e log de diagnóstico (comunica, DTCs após apagar e reler). Você precisa do primeiro dump real e do primeiro resultado de gravação, não de bancada.
3.  **Mapear o que a comunidade sabe sobre checksum da MED17**: fóruns, repositórios abertos, documentação de ferramentas open source. Decide se existe descrição pública por variante e se o checksum declarativo é viável no MVP.

Advogado não entra aqui: enquanto o trabalho é kernel, bancada e ECU própria na mesa, não há terceiro envolvido. Termo ao dono do carro, contrato com a oficina e seguro são **critério de entrada da Fase 1**, quando o primeiro arquivo vai para um carro de cliente. O que é jurídico mas vira regra de engenharia desde o dia 1, sem custo: nenhum byte de dump em repositório público; corpus com VIN tratado como dado pessoal (criptografado, acesso registrado, anonimizado por família quando a flash permite); plugin nunca desliga TPROT nem patcha rotina de verificação.

**Critério de saída:** tabela de ferramentas com pelo menos a da oficina preenchida; um dump real com `origin` e `dump_kind` conhecidos; decisão registrada sobre a fonte do algoritmo de checksum; lista das variantes de checksum presentes nas ECUs compradas (comprar pelo `hw_id`, não pelo preço; 2 a 3 ECUs cobrem 2 a 3 variantes, e o critério de pronto é por variante); acordo de X horas por semana de Flex em bench com a oficina, e chicote com pinout por variante; nome do responsável pela ECU de sacrifício e do segundo humano.

Se a Fase −1 concluir que não há descrição pública do checksum da MED17, as semanas 3 a 6 viram 3 a 12, e o MVP de auditoria sai só com `verify` nas variantes com golden e `unknown_variant` nas demais, sem recálculo.

### O fluxo de quem usa StageX (referência de mercado)

Quem usa StageX quase sempre lê e grava com o **Flex**, da própria Magicmotorsport; os dois foram desenvolvidos em paralelo como ecossistema. O fluxo é por arquivo, sem link vivo: o Flex lê a ECU (OBD, bench ou boot) e gera um arquivo; o arquivo é subido no StageX no navegador, que identifica família e versão, mostra mapas e soluções de um clique, e devolve o modificado para download; o Flex grava de volta e faz a correção de checksum. O StageX não faz a correção final. Extensão do arquivo e eventual criptografia do container não aparecem nas fontes públicas; é o que a tarde na oficina responde.

Consequências: o ponto de entrada desta plataforma é o mesmo deles, um arquivo exportado pela ferramenta; recálculo de checksum vale menos no fluxo OBD, porque a ferramenta já faz, e o valor está no *verify* independente e na auditoria; recálculo próprio volta a valer em bench/boot e nas famílias que a ferramenta não cobre (fase 1). Fontes: [Viezu, StageX com Flex](https://viezu.com/blog/why-use-magic-motorsport-stagex-with-flex/), [Viezu, recursos do StageX](https://viezu.com/blog/key-features-stagex-tuning-software/), [Tuning-shop, funções do Flex](https://tuning-shop.com/blogs/magic-motorsport-flex-functions-and-benefits-guide/).

### Primeiros ganhos (ordem de entrega, revisada na v5)

A revisão mudou o MVP: a maioria das oficinas brasileiras compra arquivo de file service, não edita mapa. O primeiro produto é **auditoria e verificação**, que exercita kernel, diff, plugin e proveniência sem a responsabilidade de escrever no carro. Os prazos são de uma pessoa; a semana 1 começa com a resposta à pergunta 1 da seção Revisão (de onde vem o algoritmo de checksum), senão nada abaixo vale.

1.  **Semana 1: acordo de oráculo com a oficina.** Ela grava, ela lê o diagnóstico, você recebe hash e log. Sem isso não há `golden_field`; com `golden_concordant` dá para desenvolver, não para lançar plugin.
2.  **Semana 1 a 3: SPEC-001 e kernel** com multi-memória, `dump_kind`, `apply`/`release`, os 12 invariantes. CLI local.
3.  **Semana 3 a 6: verify independente da MED17** por variante de checksum, golden em bancada. O CLI diz "este arquivo é íntegro" e "este arquivo é de fábrica ou já modificado" (registro de hashes stock).
4.  **Semana 6 a 9: auditoria de arquivo de terceiro.** Oficina sobe original + arquivo do file service, recebe diff por mapa (XDF importado), verify e relatório de uma página assinado para a ordem de serviço. Primeiro produto cobrável.
5.  **Semana 9 a 12: identificação automática e detecção heurística** para arquivos sem XDF, com gate nível 1 e rótulos em estado `proposed`.
6.  **Semana 12 a 16: edição e export** via CLI/tabela HTML simples, gate completo, piloto pago com a oficina parceira, single-tenant (uma instância por cliente).

## Fundações: o núcleo confiável

O produto é a confiabilidade; o software em volta é embalagem. Por isso a arquitetura tem um núcleo pequeno, construído com rigor de software crítico, e tudo o mais é consumidor dele. Se o núcleo estiver certo, um bug na API ou no editor custa uma correção; se o núcleo estiver errado, custa o carro de um cliente e a reputação do produto.

### O que está dentro e o que está fora do núcleo

*(diagrama: ver o artefato HTML do ADR)*
*núcleo · 4 peças + corpus; todos os consumidores importam o mesmo pacote*

A fronteira é clara: o núcleo é uma biblioteca Python pura. Não abre arquivo, não fala com banco, não conhece HTTP. Recebe bytes e objetos, devolve bytes e objetos. É isso que permite testá-lo exaustivamente, rodá-lo em CLI, worker e até no navegador (via Pyodide ou port) com o mesmo comportamento.

### Por que todos dependem disso estar 100% correto

| Consumidor            | O que ele faz                                     | O que acontece se o núcleo falhar                                                          |
|-----------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------|
| Export (worker)       | Materializa original + patches e corrige checksum | Arquivo gravado no carro não liga, ou liga com valor errado numa célula que ninguém editou |
| Editor                | Mostra mapas e aceita edições                     | Mostra tabela no offset errado; o tuner edita "ignição" e está mexendo em outra coisa      |
| Diff e auditoria      | Compara versões e responde "o que mudou"          | Auditoria mente; oficina não consegue provar o que entregou                                |
| Bancada virtual       | Valida antes do export                            | Aprova arquivo perigoso ou bloqueia arquivo bom; nos dois casos a confiança no gate acaba  |
| Parceiros de hardware | Embarcam o núcleo no fluxo deles                  | Bug sai com o nome deles; contrato acaba                                                   |
| Corpus e detecção     | Rótulos nascem de edições confirmadas             | Núcleo errado gera rótulo errado; o dado que deveria melhorar o sistema o envenena         |

### Dois estágios: `apply` e `release`

A materialização é separada em dois estágios com dois hashes, porque correção de checksum quebra inversibilidade. `apply(o, P) → UnverifiedImage` é puro e inversível, sem checksum. `release(UnverifiedImage, plugin) → ReleasedImage` aplica `checksum_patches` e roda o gate. `UnverifiedImage` não expõe `.bytes` e não é serializável; só `gate.release()` constrói `ReleasedImage`, e import-linter proíbe `kernel` e `plugins` de importar `gate`. O compilador impede o bypass, não um teste.

### Invariantes do kernel de binário

Cada invariante é um teste de propriedade que roda em CI com milhares de entradas geradas, e uma asserção em runtime na função correspondente. Se a asserção falhar em produção, o job aborta e abre incidente S1 automaticamente. Os invariantes 1 a 8 valem sobre `apply`; 9 a 12 sobre `release` e proveniência.

1.  **Determinismo.** `apply(o, P)` chamado duas vezes, em máquinas diferentes (x86 e arm64), devolve bytes idênticos. Proibido `struct` com formato nativo (`@`, `=`) e `numpy.frombuffer` sem byte order explícito; lint bloqueante. O kernel não contém float.
2.  **Composição.** Para todo `k`, `apply(o, P) == apply(apply(o, P[:k]), P[k:])`. Reaplicar um patch já aplicado falha na precondição (4), nunca aplica em silêncio.
3.  **Contenção.** Para todo patch `p`, `(p.memory_id, [p.offset, p.offset + p.length))` está inteiramente dentro de uma região `calibration` daquela memória. `offset` é relativo ao início da memória (`base_address` só para exibição); `len(before) == len(after) == length > 0`. Qualquer byte fora é rejeitado antes de qualquer escrita.
4.  **Precondição de patch.** `before` de `P[i]` é comparado com `apply(o, P[:i])`, nunca com `o`. Falha é conflito, nunca sobrescrita silenciosa.
5.  **Localidade.** Bytes fora da união dos ranges de `P` são idênticos entre `o` e `apply(o, P)`, em todas as memórias.
6.  **Inversibilidade.** `invert(P)` é `P` em ordem reversa com `before` e `after` trocados; `apply(apply(o, P), invert(P)) == o` byte a byte. `diff(o, apply(o, P))` devolve o conjunto canônico de patches disjuntos, ordenado por `(memory_id, offset)`, tal que `apply(o, diff(...)) == apply(o, P)`.
7.  **Ordem canônica.** O kernel normaliza patches disjuntos para a ordem `(memory_id, offset)` antes de hashear, então reordenar patches disjuntos não muda o hash. Patches sobrepostos exigem `Version.overlaps[]` (pares de `patch_hash` com ordem); sem isso `apply` rejeita.
8.  **Forma preservada.** A saída tem o mesmo `dump_kind`, as mesmas memórias, os mesmos `base_address` e tamanhos do original. Export de um parcial é um parcial. Patch nunca redimensiona.
9.  **Checksum contido e localidade de release.** Todo patch devolvido por `checksum_patches` está em região `checksum`; fora disso o kernel rejeita o conjunto inteiro. `release(u)` difere de `u` apenas em bytes de região `checksum`. Regiões `calibration` e `checksum` são disjuntas; layout que viole isso é rejeitado.
10. **Release verificado e veredito imutável.** `release` devolve `ReleasedImage` só com `verify` verde e veredito `passa` ou `alerta`; `bloqueia` lança. `ReleasedImage.verdict` é imutável, e export com `alerta` exige `Event{alert_ack}` referenciando `sha256(release)`.
11. **Migração de patches.** Re-análise com plugin novo cria nova `Version` e só migra patches cujo `before` continua batendo *e* que satisfazem Contenção sob o novo layout; os demais viram conflito explícito com motivo (`before_mismatch` ou `out_of_region`).
12. **Proveniência completa e reprodutível.** `patch_hash = sha256(JCS({memory_id, offset, length, before, after}))`; autor, timestamp e `map_id` ficam fora do hash. `image_hash = sha256(JCS({dump_kind, memories: [{memory_id, base_address, size, sha256(bytes)}]}))` com memórias ordenadas. Toda saída carrega `image_hash(o)`, `image_hash(apply)`, `image_hash(release)`, a lista canônica de `patch_hash`, `layout_hash`, versão do kernel, de cada plugin e das regras do gate, `sha256(gate_report)`, `verdict` (e o `event_id` do ack se `alerta`), versão exata do Python e `build = {kind: image | lockfile, value, platform}`. Export com `kind = lockfile` (CLI no laptop) recebe `reproducibility: best_effort` e não serve para golden. JSON canônico é RFC 8785 (JCS).

### Contrato do plugin de ECU e suíte de conformidade

Um plugin é código escrito por alguém que conhece uma família de ECU, muitas vezes de fora do time. O núcleo não confia nele: cada plugin passa por uma suíte de conformidade que roda contra o corpus daquela família, e só é publicado com veredito verde.

| Função                                      | O que a conformidade exige                                                                                                                                                                                                                          | Como se mede                                                                                                                                           |
|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `identify`                                  | Identifica corretamente todo dump do corpus da família; discrimina 100% dos pares com `sw_id` igual e variante de checksum diferente; devolve `None` ou confiança \< 0,5 para dumps de outras famílias e para bytes aleatórios; nunca lança exceção | Corpus positivo e negativo; fuzzing com 10⁵ entradas aleatórias e mutadas                                                                              |
| `verify` em arquivo com checksum desativado | Devolve `bypassed`, com o patch da rotina de verificação localizado, para todo arquivo do corpus rotulado como "checksum off"; nunca `fail`                                                                                                         | Corpus negativo de arquivos de file service e de outras ferramentas                                                                                    |
| `layout`                                    | Regiões não se sobrepõem, cobrem o arquivo inteiro, regiões de emissão marcadas `protected`; para dumps conhecidos, bate com o layout de referência revisado por humano                                                                             | Validação estrutural + comparação com golden layout                                                                                                    |
| `checksums` e `verify`                      | Todo dump original do corpus passa em `verify`; 1 byte alterado em região coberta falha em `verify`; 1 byte alterado fora de qualquer região de checksum não altera o resultado (detecta região declarada errada)                                   | Por região: 1.000 posições uniformes + 64 bytes de cada borda + bordas de cada bloco, 100% de detecção na amostra em PR; cobertura completa no nightly |
| `checksum_patches`                          | Após aplicar, `verify` passa; o resultado bate byte a byte com o golden file; todos os patches em região `checksum`                                                                                                                                 | Golden files (regras de oráculo abaixo) + invariante 9                                                                                                 |
| `hints`                                     | Opcional; todo hint aponta para região `calibration`; nenhum hint para região `protected`                                                                                                                                                           | Validação estrutural                                                                                                                                   |
| Comportamento geral                         | Puro: sem I/O, sem rede, sem estado global, sem threads; tempo máximo por chamada; memória máxima                                                                                                                                                   | Sandbox na suíte com limites; import proibido de `os`, `socket`, `subprocess`                                                                          |

A suíte é a mesma para plugin interno e externo, e o resultado dela é publicado junto com o plugin (quantos dumps, quais variantes de checksum, quais mutações). O tenant vê isso antes de confiar numa família. No MVP não existe plugin de terceiro; quando existir, roda em subprocesso com seccomp, sem rede, sem credencial no ambiente, comunicação por bytes em stdin/stdout. Proibir imports em Python não é sandbox.

### Golden files: quem é o oráculo

- O oráculo é **delegado**: o projeto é software e não tem ferro próprio. Três níveis de golden, do mais forte ao mais fraco: `golden_field`, o binário foi gravado pela oficina numa ECU real (carro ou ECU dela) e depois a ECU comunica por diagnóstico, apresenta zero DTC de memória ou checksum (P0601, P062F e similares) após apagar e re-ler, e, quando a ferramenta reporta o checksum interno, bate; a oficina devolve só dados (hash e log), registrados no `oracle:`. "Inicializou" não basta: MED17/EDC17 com checksum errado liga e comunica, só grava DTC e corta injeção. `golden_concordant`, duas ferramentas independentes produzem o mesmo resultado para o mesmo arquivo; 100% software, serve para desenvolvimento, não para release. `candidate`, uma ferramenta só. Ferramentas divergem (uma recalcula, outra patcha a rotina de verificação); opinião de ferramenta não é verdade. Release de plugin exige `golden_field` por variante.
- Nenhum hash em `tests/golden/` pode ter sido produzido por código deste repositório. Cada hash registra oráculo, versão e data; PR sem `oracle:` no corpo falha no guardrail.
- Golden é por **variante de checksum** (hardware + método), não por família. O critério de pronto do plugin conta variantes, não dumps.
- Dupla implementação no MVP é honesta: a "segunda implementação" é o oráculo externo (ferramenta + bancada) sobre o corpus, não um segundo código do mesmo autor. Quando houver segundo código, ele vem de fonte diferente e a ADR registra a fonte de cada um.
- Anonimização e golden não se misturam: zerar VIN na flash quebra o checksum. Decisão: o corpus de checksum não é anonimizado; é dado pessoal com consentimento, criptografado, acesso registrado, nunca em repositório público. Bytes anonimizados servem só para detecção de mapas.

### Gate de verificação: o único caminho para fora

Nenhum binário sai do sistema sem passar pelo gate, e o gate é uma função do núcleo, não uma etapa da API que alguém pode pular. Ele roda duas vezes: antes de aceitar o original (o arquivo que entrou é íntegro?) e depois da materialização (o arquivo que vai sair é íntegro e plausível?).

- **Entrada:** hash confere com o declarado; `identify` com confiança acima do limiar ou confirmação manual registrada; `verify` verde. Falha em qualquer um marca o artefato como `suspeito` e bloqueia edição.
- **Saída:** todos os invariantes do kernel; `verify` verde pós-fix; regras de plausibilidade nível 1 por categoria de mapa; nenhum patch em região `protected`.
- **Veredito ternário:** `bloqueia` só para o fisicamente impossível ou estrutural: fora da faixa do sensor, eixo não monotônico, região protegida, checksum, duty de bico acima de 100%. `alerta` só para plausibilidade; exporta com confirmação explícita registrada em evento com o texto do alerta. `sem achados` (nunca "passa": o gate não aprova, só não achou nada). Todo relatório abre com: "Este gate verifica integridade do arquivo e plausibilidade célula a célula. Não verifica combinação entre mapas, comportamento do firmware nem o motor real." O gate nunca devolve só booleano.
- **Faixas chaveadas, não únicas:** a faixa de plausibilidade é função de (categoria, tipo de mapa: base, correção, limite ou flag; combustão SI ou CI; combustível: gasolina, E27, E100, flex por eixo de etanol, diesel; unidade canônica após conversão raw→físico). Mapa de correção testa só amplitude relativa; flag e limitador não testam faixa; suavidade só em mapas ≥ 2×2 com valores não binários. Regra sem combustível declarado não roda. Exemplo (SI gasolina, mapa base): ignição −10° a 45°, com teto 30° em células acima de 50 kPa relativo de boost; λ 0,75 a 1,15; CI: λ ≥ 1,15. Faltam e entram por categoria: pressão de rail, tempo morto e vazão de bico, limitadores de torque e rotação, EGT alvo, VVT, boost absoluto vs relativo, duty de wastegate, limites de STFT/LTFT.
- **"Diff acima de limiar" não é regra de alerta:** o tuner existe para sair da faixa OEM; um stage 1 muda boost em 30%. O diff vai no relatório como informação, não como alerta.
- **Dupla implementação onde possível:** para famílias com algoritmo de checksum conhecido, o núcleo calcula com a implementação própria e com uma implementação de referência independente; export só com as duas concordando. Divergência é bug de plugin e vira S1.
- **Faixa física só com categoria revisada:** para mapa sem categoria `reviewed`, o gate testa apenas monotonicidade de eixo e suavidade, lista o mapa em "não testado: faixa física" e emite um `alerta` fixo: "você editou um mapa cujo significado não foi confirmado".
- **Alert fatigue é medido por regra, não por meta global:** fração de alertas confirmados em menos de 5 s sem alterar o mapa; regra acima de 50% nessa fração, por família, é rebaixada a informativo e revisada. Tenant pode silenciar uma regra por projeto com justificativa registrada. Uma meta global de "menos de 10% de alertas" viraria pressão para afrouxar regras.
- **Fail-closed:** se a tabela de faixas, a dupla implementação ou o plugin estiverem indisponíveis, o export é bloqueado, nunca liberado por ausência de verificação.

### Práticas de engenharia do núcleo

| Prática                        | Ferramenta                                                                         | Regra no CI                                                                                                                                                                                                      |
|--------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Teste de propriedade           | Hypothesis                                                                         | Cada invariante tem um teste com ≥ 2.000 exemplos; `max_examples` sobe em build noturno                                                                                                                          |
| Golden files                   | Corpus versionado (DVC ou LakeFS), hashes no repositório                           | Qualquer mudança em hash esperado exige PR separado com justificativa e dois revisores                                                                                                                           |
| Fuzzing                        | Atheris (libFuzzer para Python)                                                    | Parsers e `identify` rodam 10 min por PR, 8 h em noturno; crash é bloqueante                                                                                                                                     |
| Mutation testing               | mutmut                                                                             | Score ≥ 90% no pacote `core`, medido no nightly com ratchet que só sobe; não bloqueia merge (custa horas por PR)                                                                                                 |
| Precisão da heurística         | Conjunto de validação com `MapDef` em estado `reviewed`                            | Acerto = IoU do range de bytes ≥ 0,95 e dims iguais; precisão, recall e F1 em k = 50 por família; validação nunca contém dumps do tenant que gerou o rótulo                                                      |
| Design by contract             | Pré/pós-condições explícitas (`icontract` ou asserts próprios), ativas em produção | Falha de contrato em produção aborta o job e abre incidente                                                                                                                                                      |
| Tipagem estrita                | mypy `--strict`, Pydantic nos modelos de borda                                     | Zero `Any` no `core`                                                                                                                                                                                             |
| Cobertura                      | coverage.py com branch coverage                                                    | 100% de linhas e ramos no `core`; o resto do sistema sem meta rígida                                                                                                                                             |
| Build reprodutível             | Dependências pinadas com hash, imagem com digest fixo, SLSA nível 2 (meta nível 3) | O digest da imagem vai no relatório de proveniência de cada export                                                                                                                                               |
| Revisão (rito para uma pessoa) | O time é uma pessoa; "dois revisores" seria desligado na primeira semana           | PR em caminho de fundação fica aberto ≥ 24 h antes do merge (CI confere o timestamp), checklist de auto-revisão preenchido no corpo, e, quando há golden, aprovação do tuner de referência nomeado em CODEOWNERS |
| Versionamento                  | Semver no `core` e em cada plugin                                                  | Qualquer mudança que altere um byte de saída para alguma entrada do corpus é *major*; detectado automaticamente rodando o corpus nas duas versões                                                                |
| Regressão viva                 | Todo bug em produção vira dump + caso no corpus antes da correção                  | PR de correção precisa referenciar o caso                                                                                                                                                                        |

### Padrões escritos antes do código

- **SPEC-001 Kernel:** formato de `Patch`, semântica de `Version`, regras de ordem e sobreposição, campos de proveniência. Com exemplos canônicos e vetores de teste.
- **SPEC-002 EcuPlugin:** o protocolo, o schema de `MemoryLayout` e `Identification`, limites de tempo e memória, política de compatibilidade (o que é breaking), processo de publicação e a suíte de conformidade como parte da spec.
- **SPEC-003 Definições:** schema JSON de `MapDef` e `Definition`, unidades e fatores, regras de conversão de e para XDF e A2L, com round-trip obrigatório.
- **SPEC-004 Gate e taxonomia de vereditos:** o que bloqueia, o que alerta, formato do relatório, como o usuário confirma um alerta e o que fica registrado.
- **SPEC-005 Proveniência:** o que todo artefato e todo evento carregam; formato exportável (JSON canônico, assinado).
- **ADR por decisão:** escolha de Hypothesis, de dupla implementação de checksum, de Python puro no núcleo, de corpus versionado fora do git. Esta página é a ADR-000.

### Estrutura do repositório `core`

    core/                      # repositório público
      src/core/
        kernel/                # Artifact, Patch, Version, apply, release, diff, invert
        plugins/_contract.py   # Protocol EcuPlugin, Dump, MemoryLayout, Identification
        gate/                  # verify de entrada e saída, regras nível 1, veredito
        provenance/            # evento, relatório, JCS, cadeia de hashes
        definitions/           # MapDef, Definition, conversores XDF/A2L
        conformance/           # suíte que todo plugin roda (exposta como workflow reutilizável)
      tests/
        properties/            # Hypothesis, um arquivo por invariante (test_inv_*.py)
        golden/                # só hashes + oracle; nenhum byte de dump
        fuzz/                  # alvos Atheris
      specs/                   # SPEC-001 a 005, ADRs
      guardrails/              # check.py, ratchet.json, ruleset.json
      .github/workflows/

    ecu-plugin-bosch-med17/    # repositório privado; um por família
    corpus/                    # repositório privado; DVC, nightly, runner efêmero

Testes fora do pacote (não vão para a wheel). Plugins de família ficam em repositórios privados que consomem a conformidade como workflow reutilizável; o `core` público carrega só o contrato. API, workers, CLI e editor dependem de `core` por versão fixada; subir a versão num consumidor é um PR com o relatório de corpus anexado.

### Critério de "pronto" de cada peça

| Peça                          | Está pronta quando                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Kernel                        | Os 12 invariantes têm teste de propriedade e asserção em runtime; SPEC-001 publicada com vetores de teste, multi-memória e `dump_kind` desde a primeira versão; `apply` + `release` do corpus inteiro em \< 1 s por dump; determinismo verificado em x86 e arm64 sobre o corpus; implementação de referência ingênua de `apply` (≤ 50 linhas, só stdlib) concordando byte a byte em teste diferencial; script de reprodução da proveniência usa só stdlib |
| Primeiro plugin (Bosch MED17) | Passa a conformidade para cada variante de checksum coberta (hardware + método), com ≥ 5 dumps por variante; cada variante tem ≥ 1 `golden_field` devolvido pela oficina (hash + log de diagnóstico); o tuner de referência, que não é o mesmo que pede o arquivo pronto, validou o layout                                                                                                                                                                |
| Gate                          | Não existe caminho de código que produza um binário de saída sem passar por ele (verificado por teste de arquitetura, import-linter); relatório sempre lista o que testou e o que não testou; dupla implementação ativa na primeira família                                                                                                                                                                                                               |
| Proveniência                  | Todo export reproduzível a partir do relatório sozinho (original + patches + versões + digest) por um script independente, em máquina limpa                                                                                                                                                                                                                                                                                                               |
| Corpus                        | Pipeline de ingestão com anonimização e consentimento; versionado; cada dump com origem, família, versão de software e status de revisão humana                                                                                                                                                                                                                                                                                                           |

**O ponto que organiza tudo:** enquanto o núcleo não atender esses critérios, nenhum consumidor é prioridade. O CLI de checksum existe para forçar o núcleo a existir; o editor existe para forçar o gate a ser usado. A ordem é do centro para fora.

## Guardrails, CI e stack gratuita

Padrão que pode ser afrouxado por conveniência numa sexta à noite não é padrão. Esta seção define como os padrões das fundações ficam fisicamente difíceis de remover, o que a CI roda, e com que ferramentas, todas gratuitas ou open source, no MVP.

### Quatro camadas de garantia

Nenhuma camada sozinha segura; juntas, afrouxar um padrão exige uma mudança visível, revisada por duas pessoas, com justificativa escrita, e ainda assim deixa rastro.

| Camada                                            | O que faz                                                                                                                                                                                                                                                                                                                                               | Como é implementada                                                                                                                                                                                                                                                                                                                                                                                   | O que ela não impede                                                                      |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| 1 · Ruleset no hospedeiro                         | Merge só por PR, checks obrigatórios, sem force-push, sem bypass list. Com time de uma pessoa, 0 aprovações (o autor não aprova o próprio PR; 2 aprovações = merge impossível). Admin sempre pode editar o ruleset; "inclusive para admin" não existe                                                                                                   | Ruleset exportado como JSON e versionado em `guardrails/ruleset.json`; audit log do GitHub mostra quando foi alterado                                                                                                                                                                                                                                                                                 | É rastro de auditoria, não barreira. A barreira real é a camada 2                         |
| 2 · Guardrail na CI, executado a partir de `main` | Um job que falha o PR se: um caminho de fundação mudou sem label `foundation-change`; kernel, gate ou contrato mudou sem spec ou ADR junto; golden files mudaram no mesmo PR que código ou sem `oracle:`; um ratchet desceu; apareceu `skip`, `xfail`, `type: ignore`, `noqa` ou `pragma: no cover` em `core/`; o número de arquivos de invariante caiu | No evento `pull_request` o workflow que roda é o da branch do PR, então um PR que edita o guardrail rodaria a versão editada. Por isso o job usa `pull_request_target` (opened, synchronize, labeled, unlabeled) e `pull_request_review`, faz checkout **apenas do base ref** e lê o diff e os metadados pela API; nunca executa código da branch do PR. O script que julga o PR é sempre o de `main` | Quem tem acesso total e má intenção; impede o afrouxamento por pressa, que é o risco real |
| 3 · Ratchets                                      | Limiares que só sobem: cobertura (100%), número de invariantes (12), exemplos de Hypothesis, minutos de fuzz, dumps mínimos por variante no corpus. Mutation score (≥ 90%) é ratchet de **release**: o workflow de release lê o último relatório do nightly e falha se abaixo do JSON                                                                   | Arquivo `guardrails/ratchet.json` comparado com a versão na base do PR; o CI confere que `pyproject.toml` reflete os mesmos números                                                                                                                                                                                                                                                                   | Em PR só impede baixar o número no JSON; a métrica real é cobrada no release              |
| 4 · Testes de arquitetura                         | O código não consegue violar a estrutura: `core` não importa I/O, rede, subprocess nem framework; camadas kernel → proveniência → plugins → gate → conformance; plugins não importam uns aos outros; não existe caminho que produza binário de saída sem passar pelo gate                                                                               | `import-linter` com contratos versionados; teste que percorre o grafo de chamadas de `export`                                                                                                                                                                                                                                                                                                         | Erros de lógica dentro das camadas; para isso existem invariantes e golden files          |

### Pipeline de CI do repositório `core`

| Workflow             | Quando                                                                                              | O que roda                                                                                                                                                                                                                                                                                                                                                                        | Bloqueia merge?                   |
|----------------------|-----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------|
| `core-ci`            | Todo PR e push em main                                                                              | ruff (lint + formato); mypy `--strict` sem `Any`; import-linter; pytest com branch coverage e `fail_under = 100`; Hypothesis com 2.000 exemplos e seed fixa; golden do corpus rápido (≥ 20 dumps); fuzz de 10 min por parser                                                                                                                                                      | Sim                               |
| `guardrails`         | Todo PR, inclusive ao mudar labels                                                                  | As regras da camada 2 e 3 acima                                                                                                                                                                                                                                                                                                                                                   | Sim                               |
| `plugin-conformance` | Reutilizável; chamado pelo repositório de cada plugin                                               | Sandbox (sem import de os, socket, subprocess); identify no corpus positivo e negativo; 10⁵ entradas de fuzz; mutação byte a byte com detecção de 100% nas regiões de checksum; golden de `fix_checksums`; relatório JSON publicado junto com o plugin                                                                                                                            | Sim, para publicar o plugin       |
| `nightly`            | Diário, 03:17 UTC, ou manual; vive no **repositório privado do corpus**, que clona o `core` por SHA | Hypothesis com 50.000 exemplos e seed aleatória; fuzz em matriz de alvos × 2 h (um job não pode passar de 6 h) com corpus de fuzz acumulado; corpus completo byte a byte; mutation testing com score contra o ratchet; falha abre issue S1 automaticamente                                                                                                                        | Não bloqueia PR; bloqueia release |
| `release`            | Tag `vX.Y.Z`                                                                                        | Versão da tag igual ao `pyproject`; build reprodutível com `SOURCE_DATE_EPOCH`; corpus completo verde e mutation score do último nightly acima do ratchet; SBOM (syft); scan (grype, falha em high); assinatura keyless com cosign; atestado de proveniência SLSA 3 via `slsa-github-generator` desde o primeiro release, e a proveniência do export usa o `build_id` do atestado | Sem release sem tudo verde        |

Regra de semver automatizada: o `nightly` e o `release` rodam o corpus nas duas versões (base e candidata); qualquer byte de saída diferente para qualquer dump do corpus marca a mudança como *major* e o release falha se a versão não subiu o major.

### Rito de mudança nas fundações (time de uma pessoa)

1.  Abrir ou atualizar a spec ou ADR em `specs/` no mesmo PR, dizendo o que muda e por quê.
2.  Aplicar o label `foundation-change`; sem ele o guardrail falha.
3.  PR fica aberto ≥ 24 h contadas do **último commit** da branch (contar do `created_at` seria burlável: abrir vazio, esperar, empurrar a mudança real). Um workflow `schedule` horário reavalia os PRs abertos com o label e atualiza o check via API, porque o check não roda sozinho quando as 24 h vencem.
4.  Checklist de auto-revisão preenchido no corpo do PR; quando há golden, aprovação do tuner de referência nomeado em CODEOWNERS.
5.  Se golden files mudam, PR separado só com eles, label `golden-change` e `oracle:` no corpo; o PR de código referencia esse.
6.  Se algum ratchet precisa descer (não deveria), é uma ADR própria explicando, e o número volta a subir com prazo.

### Segurança do pipeline

- `permissions: contents: read` no topo de todo workflow; `id-token: write` só no job de assinatura.
- Todas as actions pinadas por SHA completo; Dependabot para `github-actions` e `pip` (atualiza os hashes do lockfile).
- Nenhum workflow do repositório público usa runner self-hosted: "só executa em main e PRs de membros" é intenção, não configuração, e qualquer `runs-on: self-hosted` disparado por `pull_request` roda código de fork. O runner self-hosted é efêmero (JIT, VM descartável) e registrado só no repositório privado do corpus.
- Actions settings: aprovação obrigatória para todos os colaboradores externos.
- `pull_request_target` nunca faz checkout do head do PR.
- Nenhum byte de dump em repositório público: só hashes.

### Stack gratuita ou open source para o MVP

Tudo abaixo custa zero em dinheiro; o custo é uma máquina para o self-hosted e o tempo de configurar. A restrição importante está na primeira linha.

| Função                    | Escolha                                                                                           | Por quê                                                                                                                                                                                               | Atenção                                                                                                                                                                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Hospedagem de código e CI | GitHub: `core` público, corpus e plugins de família em repositórios privados                      | Actions ilimitado em público; rulesets e checks obrigatórios funcionam em público no Free                                                                                                             | No GitHub Free, proteção de branch e revisores obrigatórios só existem em repositório público; para privado é Pro (pessoal) ou Team (organização). Forgejo self-hosted é a saída de emergência, com os mesmos workflows |
| Runner de CI              | Runner self-hosted (qualquer Linux) para nightly e fuzz; hospedado para PR                        | Fuzz de 8 h e mutation testing estouram qualquer cota gratuita                                                                                                                                        | Runner isolado do corpus de produção; só corpus de teste                                                                                                                                                                |
| Corpus versionado         | DVC com remote em Backblaze B2 ou Cloudflare R2 (free tier), bucket privado, versionamento ligado | Dumps fora do git, versionados por hash, com `dvc pull` só no repositório privado; MinIO community entrou em modo de manutenção em 2025 e expor um VPS para a CI hospedada é superfície desnecessária | Cópia mensal com `rclone` para disco local; credencial só no repositório privado                                                                                                                                        |
| Testes                    | pytest, Hypothesis, Atheris, mutmut, coverage.py                                                  | Todos OSS, maduros, sem serviço externo                                                                                                                                                               | Atheris precisa de clang no runner                                                                                                                                                                                      |
| Qualidade estática        | ruff, mypy, import-linter, pre-commit                                                             | Rápidos, sem SaaS                                                                                                                                                                                     | —                                                                                                                                                                                                                       |
| Supply chain              | pip-tools com hashes, syft, grype, cosign (sigstore keyless), SLSA 3 via generator oficial        | Reprodutibilidade e assinatura sem gerenciar chave                                                                                                                                                    | Keyless depende de OIDC do GitHub                                                                                                                                                                                       |
| Segredos                  | SOPS + age no repositório de infra                                                                | Segredos versionados e criptografados, sem Vault no MVP                                                                                                                                               | Chave age em dois lugares físicos                                                                                                                                                                                       |
| Observabilidade local     | Prometheus, Grafana, Loki, Tempo em docker compose                                                | Mesma stack da v1, só menor                                                                                                                                                                           | —                                                                                                                                                                                                                       |
| Banco, fila, storage      | Postgres, NATS JetStream, MinIO em docker compose                                                 | Idênticos aos de produção; o core nem sabe que existem                                                                                                                                                | —                                                                                                                                                                                                                       |
| Rastreamento de trabalho  | Issues do próprio Forgejo/GitHub, ADRs em markdown                                                | Nada a pagar, tudo ao lado do código                                                                                                                                                                  | —                                                                                                                                                                                                                       |

**Runner e repositório público:** PR de fork nunca roda em runner self-hosted com credencial de corpus (é RCE conhecido). O runner self-hosted só executa em `main` e em PRs de membros; o corpus usado em PR é um subconjunto sem dado pessoal e sem firmware, acessível sem credencial. Nenhum byte de dump entra em repositório público: só hashes.

**Decisão registrada (2026-10-17):** GitHub desde o início. Enquanto o plano for Free, o `core` fica público (o valor está no corpus e nos plugins de família, que ficam em repositórios privados); se o `core` precisar ser privado, o plano Pro destrava proteção de branch e revisores obrigatórios. Forgejo fica como saída de emergência, já que os workflows são compatíveis.

## Revisão adversarial e decisões v5

Um revisor independente (staff engineer de sistemas críticos, tuner de bancada e investidor, em uma só persona) atacou a versão 4 deste documento. O que era claramente certo já foi aplicado nas seções anteriores; o que fica aqui são as brechas que ainda exigem decisão, o que foi cortado do MVP, as melhorias de alto valor e as perguntas abertas.

### O que mudou nas seções anteriores por causa da revisão

- Modelo de dados: `Artifact` ganhou `origin`, `dump_kind` e `memories[]`; `Patch` ganhou `memory_id`; `MapDef.dtype` completo; rótulos com estado.
- Kernel: `apply` e `release` separados, 12 invariantes, determinismo provado em duas arquiteturas, sem float, JCS, `build_id` para o CLI.
- Plugin: `checksum_patches` no lugar de `fix_checksums`; `protected` por padrão; checksum declarativo; sandbox real por subprocesso quando houver terceiro.
- Golden: oráculo é ECU que inicializa em bancada; por variante de checksum; nunca produzido pelo próprio código; corpus de checksum não anonimizado e nunca público.
- Gate: faixa física só com categoria `reviewed`; taxa de alerta medida.
- Rito: para uma pessoa (24 h + checklist + tuner de referência em golden); mutation testing no nightly.
- Primeiros ganhos: MVP virou auditoria e verificação; bancada física na semana 1.
- CI: runner self-hosted protegido de PR de fork; zero bytes de dump em repositório público.

### Brechas que ainda exigem decisão

| Brecha                                             | Por que morde                                                                                                                                                                                                                             | Decisão proposta                                                                                                                                                                                             | Status                           |
|----------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| Tabela por ferramenta de leitura                   | KESS3, Flex, Autotuner exportam containers diferentes, alguns criptografados pela nuvem do fabricante; algumas corrigem checksum na gravação e nem sempre dá pra desligar. Decide se o MVP funciona com o equipamento da oficina parceira | Levantar com a oficina: ferramenta, formato exportado, se aceita arquivo externo de volta, se corrige checksum na escrita, se escrita OBD é full ou parcial. Virar tabela nesta seção                        | Aberto                           |
| Export offline                                     | O momento sem internet é o carro no elevador; o gate roda no worker                                                                                                                                                                       | O core roda local via CLI com gate e proveniência; o SaaS é corpus, definições e auditoria. Download de emergência do original em um clique, sem login complexo                                              | Decidido                         |
| "Original" que não é stock                         | Carros chegam remapeados por terceiros; rotular mapas sobre um stage 1 alheio envenena o corpus                                                                                                                                           | Registro de hashes de arquivos stock por versão de software; todo upload é classificado como stock, modificado ou desconhecido                                                                               | Decidido                         |
| WORM contra LGPD                                   | Object Lock em modo compliance impede apagar a pedido do titular                                                                                                                                                                          | Modo governance, e exclusão efetiva por destruição da chave de criptografia do artefato                                                                                                                      | Decidido                         |
| Consentimento e corpus após cancelamento do tenant | "Revogar a chave apaga tudo" conflita com corpus derivado dos dumps dele                                                                                                                                                                  | Consentimento para corpus é desacoplado da conta e registrado por dump; cancelamento sem revogação de consentimento mantém o dump no corpus; revogação purga                                                 | Precisa de contrato              |
| Direito autoral do firmware e A2L                  | Dump contém firmware Bosch; A2L de fórum é segredo industrial vazado; `core` público torna qualquer byte em `tests/` alvo de DMCA                                                                                                         | Nenhum byte de dump em repositório público; definições de origem não licenciada ficam privadas ao tenant que importou; biblioteca compartilhada só com definição criada na plataforma ou licença verificável | Decidido                         |
| Anticircunvenção (Lei 9.610, art. 107)             | Recalcular checksum provavelmente não é; desligar TPROT ou patchar rotina de verificação é discutível                                                                                                                                     | O plugin recalcula; nunca patcha a rotina de verificação nem toca TPROT. Escrito na SPEC-002                                                                                                                 | Decidido, confirmar com advogado |
| CDC e responsabilidade solidária                   | Termo de uso vincula a oficina, não o dono do carro, que pode acionar a cadeia                                                                                                                                                            | Contrato com a oficina (dados, rótulos, indenização, continuidade), termo de ciência do dono do carro no piloto, orçamento de ECU de sacrifício, avaliação de seguro de RC                                   | Aberto, precisa de advogado      |
| CONTRAN/PROCONVE                                   | Remap em si pode ser alteração de característica do veículo                                                                                                                                                                               | Termo de uso diz isso explicitamente; o produto não promete regularidade                                                                                                                                     | Decidido                         |
| Bus factor 1 com dados de terceiros                | Se o autor parar, originais de clientes ficam presos                                                                                                                                                                                      | Export em massa dos originais pelo tenant a qualquer momento; chave de decriptação em custódia com instrução escrita; tuner de referência remunerado como segundo humano e CODEOWNER de plugins e golden     | Parcial                          |
| Watermark por perturbação de map pack              | Perturbar offset quebra o mapa; perturbar fator induz edição errada; dois tenants comparando packs acham a marca                                                                                                                          | Cortado. Metadados assinados e, se precisar, mapas-isca                                                                                                                                                      | Decidido                         |
| Custo real do piloto                               | Storage é desprezível; o custo é WinOLS com módulo de checksum como oráculo secundário, ECUs de bancada, runner self-hosted e o tempo da oficina                                                                                          | Orçar: ECUs R\$ 2 a 4 mil; segunda ferramenta de referência; máquina do runner; contrapartida à oficina que não seja "licença vitalícia" (passivo perpétuo)                                                  | Aberto                           |

### Melhorias de alto valor

| \#  | O quê                                                                       | Por que vale                                                                                                                     | Custo                                      | Fase  |
|-----|-----------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------|-------|
| 1   | Oráculo delegado à oficina desde a semana 1 (ela grava, devolve hash e log) | Único oráculo real de checksum, sem ferro próprio; StageX e WinOLS não dão isso ao usuário                                       | 1 dia de acordo + horas de Flex da oficina | 0     |
| 2   | Registro de hashes stock e "este carro já foi modificado?"                  | Produto vendável sozinho (oficina, revenda de usados, seguradora, concessionária); gera corpus sem editor; ninguém faz no Brasil | 5 dias                                     | 0     |
| 3   | Auditoria de arquivo de terceiro como produto número um                     | Vende para a maioria do mercado, zero responsabilidade por escrita, exercita o núcleo inteiro                                    | 10 dias                                    | 0     |
| 4   | Checksum declarativo (descritores, não código)                              | Resolve 80% das variantes sem sandbox; dupla implementação feita uma vez                                                         | 5 dias                                     | 0     |
| 5   | Multi-memória e `dump_kind` na SPEC-001 antes do primeiro commit            | Evita a migração que o documento diz temer                                                                                       | 2 dias                                     | 0     |
| 6   | Core local via CLI com gate e proveniência offline                          | Resolve internet na oficina, elimina infra no MVP, e o arquivo nunca sai da máquina de quem tem medo de nuvem                    | 8 dias                                     | 0 a 1 |
| 7   | Relatório de export em PDF de uma página para a ordem de serviço            | Transforma proveniência em proteção jurídica da oficina; argumento de venda que WinOLS não tem                                   | 3 dias                                     | 0     |
| 8   | Datalog antes/depois no lugar do modelo físico de motor                     | Dado real, custo baixo, honesto; o mean-value model daria falsa segurança                                                        | 6 dias                                     | 1     |
| 9   | Kit jurídico do piloto                                                      | Sem isso, o primeiro carro que não liga encerra o projeto                                                                        | 3 dias + advogado                          | 0     |
| 10  | Segundo humano nomeado e remunerado                                         | Resolve bus factor, independência da validação e o rito de revisão                                                               | contínuo                                   | 0     |

### Cortado do MVP

- Todo o inventário de infraestrutura da v1: Kubernetes, Karpenter, Linkerd, Temporal, Argo CD, Terraform, Kyverno, OpenFGA, Keycloak, OpenSearch, Redis, WAF, PagerDuty, status page, Intercom, PostHog, Stripe, KMS por tenant, Sentry. No lugar: um VPS, docker compose, Postgres, MinIO ou disco, Caddy, e-mail. As interfaces finas ficam.
- Multi-tenant, billing e sub-dealers: single-tenant por oficina (uma instância por cliente) até 5 pagantes.
- Editor 2D/3D em WebGL com CRDT: tabela HTML editável resolve; 3D é demo.
- Port do core para navegador.
- SLSA 3, cosign, SBOM e grype: hashes pinados e lockfile bastam até haver usuário; voltam na v1.
- Mutation testing como bloqueio de merge e fuzz de 8 h por noite: nightly informativo com ratchet.
- Watermark por perturbação.
- Bancada virtual níveis 2 e 3 (modelo físico, HIL): substituídos por datalog antes/depois e bancada física mínima. O nível 1 fica.
- ML, TCUs, importado premium, white-label, SDK público, GDPR, SOC 2, bug bounty, chaos, k6, Schemathesis, SLO formal: nada antes de 5 oficinas pagando.
- "Semana 1 a 2: checksum MED17 do zero": sem oráculo e sem fonte do algoritmo é um mês ou mais por variante de hardware. O cronograma começa com a pergunta 1.

### Revisão por tópico (v7): seis revisores independentes

Seis revisores, cada um vendo só as seções do seu tema (kernel; plugins, checksum e corpus; gate e bancada; legal e LGPD; CI e supply chain; negócio e roadmap). O que era claramente certo foi aplicado nas seções. Resumo do que mudou e o que ficou como decisão.

| Tópico            | Aplicado nas seções                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Fica como decisão                                                                                     |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Kernel            | Idempotência trocada por composição; `invert` e `diff` definidos formalmente; ordem canônica e `overlaps[]`; `patch_hash` e `image_hash` sem metadados; `alerta` produz `ReleasedImage` com veredito imutável e `alert_ack`; migração reavalia contenção; `Patch` imutável por hash e `Version` com lista completa; `Event` com cadeia de hashes; `suspect_ack` na proveniência; pipeline sem lista própria de invariantes; implementação de referência ingênua de `apply` | —                                                                                                     |
| Plugins e corpus  | Entrada é `Dump` com memórias; `Identification` com `hw_id`, `sw_id`, `checksum_variant_id`; `verify` com `bypassed`, `signature_unverifiable`, `not_applicable`; `ChecksumRegion.kind`; descritor declarativo completo; TPROT como flag; `pii_in_flash`; golden exige diagnóstico e zero DTC; tabela de ECUs corrigida; Fase −1 com variantes e horas de bench                                                                                                            | Itens marcados "verificar" na tabela de mercado (Firefly, GM turbo, Renault TCe) confirmam na Fase −1 |
| Gate e bancada    | Faixas chaveadas por categoria, tipo de mapa, combustão e combustível; `bloqueia` só para o impossível; `passa` virou `sem achados` com disclaimer; diff deixa de ser alerta; fadiga medida por regra; fail-closed; datalog antes/depois especificado; RNFs do gate                                                                                                                                                                                                        | —                                                                                                     |
| Legal e LGPD      | Oficina controladora e plataforma operadora; base legal por finalidade; encarregado e RIPD; sem prazo de 30 dias; transferência internacional; firmware e A2L; art. 107; CDC; CTB e PROCONVE no lugar de EPA; ANPD em 3 dias úteis                                                                                                                                                                                                                                         | Tudo marcado "verificar" exige advogado antes do piloto; cotação de seguro E&O                        |
| CI e supply chain | Camada 1 reescrita como rastro, não barreira; guardrail via `pull_request_target` a partir de `main`; 24 h do último commit com reavaliação agendada; mutation score no release; segurança do pipeline em seis regras; runner só no repo privado do corpus; fuzz em matriz; B2/R2 no lugar de MinIO; SLSA 3 desde o início; infra do MVP reduzida a um VPS; estrutura `src/` com plugins em repos privados                                                                 | —                                                                                                     |
| Negócio           | Quatro riscos de negócio adicionados; 3 oficinas externas no critério de saída da Fase −1                                                                                                                                                                                                                                                                                                                                                                                  | Ver a tensão abaixo                                                                                   |

**Decisão do autor (2026-10-18): crítico bem feito, não vendável rápido.** O revisor de negócio sustentou que semanas de kernel, invariantes e conformidade antes de contato com cliente é plataforma antes de produto, e propôs vender diff + PDF em duas semanas com a regra "nenhuma abstração com menos de dois usos até a primeira venda". A posição foi ouvida e rejeitada: a tese deste ADR é que confiabilidade é o produto, e um diff que não assenta sobre um kernel com invariantes provados é exatamente o tipo de atalho que o documento existe para impedir. A ordem fica: Fase −1 de descoberta, bancada física, SPEC-001, kernel com os 12 invariantes, plugin por variante com golden, gate; só então o primeiro produto (auditoria e verificação) vai para a oficina parceira. Receita não é gate da Fase 0; é gate da Fase 1. O que fica aproveitado da revisão de negócio: os quatro riscos adicionados à tabela; a hipótese de dor a validar na Fase −1 (a oficina paga para não gravar arquivo com delete escondido, para provar ao cliente o que foi alterado, e para escolher entre file services); revenda e seguradora fora do MVP; contrapartida à parceira por contrato (licença vitalícia mais participação nas auditorias indicadas por ela, em troca de dumps rotulados e horas de tuner); validação de preço em oficinas sem relação com ela quando chegar a hora; e o cronograma convertido de semanas de calendário para horas disponíveis declaradas.

### Três perguntas antes de escrever código

1.  **De onde vem o algoritmo de checksum da MED17 e qual é a verdade sobre ele?** Engenharia reversa própria (meses, risco legal), documentação de comunidade (parcial, por variante) ou licença de módulo de terceiro (custo, e o output da ferramenta não é verdade)? Existe ECU na mesa e quem grava nela? Sem resposta, "golden file" não existe.
2.  **Qual é o conjunto de ferramentas e tipos de dump que o MVP precisa aceitar para vender a qualquer oficina, e qual deles é validado de ponta a ponta primeiro?** As travas são agnósticas; a validação delas não é. A oficina parceira não é a individualidade para a qual o produto se prepara, é o primeiro caso concreto que percorre o caminho inteiro, como o primeiro driver real que valida uma interface de banco. A tabela de ferramentas mapeia o espaço de variação (container, criptografia, correção de checksum na escrita, OBD parcial ou full) para que a ingestão cubra o espaço, não um fornecedor.
3.  **No dia em que um arquivo exportado não ligar um carro de cliente, o que acontece, quem paga a ECU e quem é o segundo humano?** Esta pergunta não bloqueia a Fase 0 (ECU própria na mesa); bloqueia a entrada na Fase 1. Se a resposta for "ninguém" para qualquer um dos três, nenhum arquivo vai para carro de terceiro.

## Requisitos não funcionais

O requisito que manda em tudo é integridade: um byte errado no binário trava o carro. Todo o resto é desenhado em torno disso.

| Requisito                   | Meta                                                                                                             | Como se garante                                                                      |
|-----------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| Integridade do binário      | Zero escrita fora do range editado; hash do original preservado                                                  | Storage imutável (WORM), toda edição é um patch sobre o original, nunca sobrescrita  |
| Reprodutibilidade           | Mesmo original + mesmos patches = mesmo binário, sempre                                                          | Patches ordenados e determinísticos; checksum calculado por plugin versionado        |
| Auditabilidade              | Quem editou o quê, quando, e com qual versão de plugin                                                           | Event log append-only por projeto; exportável para o cliente                         |
| Isolamento por tenant       | Um tenant nunca lê arquivo de outro                                                                              | Row-level security no Postgres + prefixo de bucket por tenant + chave KMS por tenant |
| Latência da análise         | Identificação + detecção heurística em \< 30 s para dump de 4 MB                                                 | Worker assíncrono, resultado por streaming (SSE/WebSocket)                           |
| Disponibilidade             | 99,5% no MVP, 99,9% na v1                                                                                        | Stateless API, fila durável, storage replicado                                       |
| Offline parcial             | Editor continua funcionando sem rede sobre um arquivo já aberto                                                  | Estado do editor no cliente, sincronização por patches ao reconectar                 |
| Portabilidade de definições | Importar e exportar XDF, A2L, CSV de mapas                                                                       | Formato interno próprio com conversores de borda                                     |
| Custo por arquivo           | Previsível, dominado por storage e CPU de worker                                                                 | Sem GPU no caminho crítico                                                           |
| Qualidade do gate           | Zero `sem achados` nos casos negativos do corpus de regressão; bloqueio falso abaixo de 1% dos exports do corpus | Corpus negativo rotulado; métrica por release                                        |
| Latência e falha do gate    | Menos de 5 s por export; fail-closed                                                                             | Regras como dados em memória; indisponibilidade de regra ou plugin bloqueia          |
| Exatidão de unidades        | Conversão raw→físico com erro ≤ 0,5 LSB em round-trip                                                            | Teste de propriedade por `dtype` e fator                                             |

## Visão geral da arquitetura

Três camadas: clientes finos, serviços síncronos stateless atrás de um gateway, e workers assíncronos que fazem o trabalho pesado sobre o binário. O binário nunca passa pela API: o cliente faz upload direto no object store com URL assinada e a API só recebe o hash.

*(diagrama: ver o artefato HTML do ADR)*
*componentes · 3 camadas, 1 fila, 2 stores*

Os serviços síncronos só leem e escrevem metadados; qualquer operação sobre o binário vira um job na fila e os workers escrevem o resultado de volta no object store e no Postgres.

## Pipeline de ingestão e análise

O pipeline é uma cadeia de estágios idempotentes; cada um grava seu resultado como artefato versionado, de modo que um estágio pode ser reexecutado com um plugin novo sem refazer os anteriores.

1.  **Upload.** Cliente pede URL assinada, envia o `.bin`, informa SHA-256 e origem (OBD, bench, boot, ferramenta). API grava `Artifact{original=true}` com bucket WORM e lock de retenção.
2.  **Identify.** Worker lê os primeiros e últimos KB e procura assinaturas: strings de software ID (Bosch `1037xxxxxx`, Siemens, Delphi), tamanho do arquivo, endianness, padrões de boot. Saída: `EcuFamily`, `SoftwareVersion` (confiança 0 a 1). Se a confiança for baixa, o usuário escolhe manualmente e a escolha vira label.
3.  **Layout.** Com a família conhecida, o plugin devolve o mapa de memória: regiões de código, de calibração, de checksum e de dados protegidos. Só a região de calibração é editável.
4.  **Map detect.** Dois caminhos rodam em paralelo e os resultados são mesclados por score:
    - *Heurística*: busca eixos (sequências monotônicas de 8 a 32 valores, 8/16 bits, com fator plausível), depois blocos retangulares adjacentes cuja variação é suave em ambas as direções. É o que o tuner faz na mão no WinOLS.
    - *Definição conhecida*: se existe `Definition` para o `SoftwareVersion` ou para um irmão próximo, aplica por offset e valida comparando eixos.
5.  **Checksum verify.** Antes de qualquer edição, o plugin recalcula os checksums do original e confere que batem. Falha marca o artefato como `suspeito`; edição só prossegue com `Event{suspect_ack}`, e todo export desse projeto carrega `input_verify: failed_acknowledged` no relatório.
6.  **Edit.** Toda edição vira um `Patch{memory_id, offset, length, before, after, map_id, author, ts}`. Nunca se grava um binário editado inteiro; ele é materializado sob demanda aplicando os patches sobre o original.
7.  **Export.** Worker chama `apply` e `release` do `core` com a versão fixada do plugin, grava como `Artifact{derived}` com `version_id`, `image_hash(apply)`, `image_hash(release)` e o relatório do gate, e devolve URL assinada de curta duração.

O pipeline não acrescenta invariantes: cada estágio chama `apply` e `release` do `core` e herda os 12 da seção Fundações. Não existe uma segunda lista para divergir.

## Bancada virtual de testes

Testar o mapa antes de gravar no carro é o diferencial mais defensável do produto, mas "ECU virtual" tem três níveis muito diferentes de dificuldade. O plano constrói do mais barato ao mais caro e cada nível já entrega valor sozinho.

| Nível                                        | O que é                                                                                                                                                                                                                                                                                                                                                         | O que pega                                                                                                                                | O que não pega                                                                                                      | Custo e fase                                                                                                                                |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| 1 · Validação estática e de plausibilidade   | Regras sobre o binário e sobre cada mapa: checksum, monotonicidade de eixos, faixa física por categoria (avanço de ignição entre −20° e 60°, lambda entre 0,65 e 1,3, boost abaixo do limite do sensor MAP), suavidade (gradiente máximo entre células vizinhas), diff contra original acima de um limiar por categoria                                         | Erro de digitação, célula estourada, eixo quebrado, patch fora de região, exagero grosseiro                                               | Interação entre mapas (ignição alta + mistura pobre + boost alto ao mesmo tempo)                                    | Baixo; MVP. Roda no worker de export e bloqueia                                                                                             |
| 1b · Datalog antes/depois (MVP, informativo) | Importa CSV do scanner ou da ferramenta, antes e depois do arquivo. Sinais mínimos: rpm, MAP/carga, TPS, λ medida e alvo, avanço, retardo por detonação, IAT, ECT, STFT/LTFT, duty de bico, boost alvo vs medido, % etanol (flex), EGT se houver. Comparação por bins rpm × carga com ≥ 20 amostras em ambos os logs; célula sem cobertura fica "não comparado" | Retardo por detonação \> 3° sustentado, \|λ − alvo\| \> 0,05 em WOT, duty de bico \> 90%, LTFT fora de ±10%, overshoot de boost \> 15 kPa | É pós-gravação: diagnostica, não previne. Nunca bloqueia                                                            | Baixo; MVP. Dado real, honesto, sem modelo                                                                                                  |
| 2 · Simulação de motor com modelo físico     | Modelo de valor médio parametrizado por motor, estimando torque, EGT, margem de detonação, duty de bico e de wastegate a partir dos mapas editados                                                                                                                                                                                                              | Combinação perigosa de mapas, bico saturando, EGT fora da faixa                                                                           | Comportamento do software da ECU; e, sem calibração do motor específico, erra detonação e EGT parecendo dinamômetro | Cortado do MVP. Só retorna quando houver datalogs suficientes por motor para validar previsto vs medido com erro de torque \< 10%           |
| 3 · ECU real em bancada com HIL              | A ECU física ligada a simulador hardware-in-the-loop que gera sinais de sensores e lê atuadores; o firmware roda de verdade com o mapa editado                                                                                                                                                                                                                  | Tudo que a ECU faz: proteções, limitadores, DTCs; o arquivo "liga" ou não                                                                 | Carga real no motor; detonação de verdade                                                                           | Cortado do MVP (meses por família). O que fica é a bancada física mínima: ECU na mesa para golden e teste de partida, não serviço agendável |

### Por que não emular o firmware da ECU

Uma ECU virtual completa exigiria emular o microcontrolador (TriCore na Bosch, PowerPC na Continental) e os periféricos, com firmware fechado e protegido. É território de equipe de engenharia reversa por anos e de risco jurídico alto. O nível 3 entrega o mesmo resultado prático (o firmware real rodando o mapa real) com hardware comum de bancada; o nível 2 entrega a parte física que o firmware não sabe.

### Arquitetura da bancada no sistema

- Um worker `validate` na mesma fila, entre `edit` e `export`. Nível 1 é obrigatório; nível 2 e 3 são opcionais e cobrados.
- Regras do nível 1 são dados, não código: tabela de faixas por categoria e por motor, versionada como `Definition`, editável por tenant avançado.
- Resultado de cada validação é um `Artifact{report}` com veredito (bloqueia, alerta, sem achados), gráficos e o hash do binário testado, ligado à versão.
- Nível 2 expõe os mesmos gráficos que um dinamômetro: torque e potência estimados por rotação, EGT, lambda, duty. É o que o tuner mostra pro cliente.
- Datalogs reais (CSV do scanner ou da ferramenta) entram pelo mesmo caminho e calibram o modelo do nível 2; o tuner compara previsto vs. medido.
- Nível 3: a bancada é um recurso agendável; o job envia o binário pra bancada, roda um roteiro padronizado (partida, marcha lenta, rampa de carga simulada) e devolve log e DTCs.

**O que é "revolucionário" de verdade aqui** não é o nível 3, que laboratórios de calibração já têm, e sim colocar o nível 1 e o 2 no fluxo de toda oficina, por arquivo, com veredito antes do export. Hoje a oficina pequena testa gravando no carro do cliente.

## Modelo de dados

O modelo separa o que é fato imutável (binários, patches, eventos) do que é conhecimento acumulado (definições, map packs). Os dois lados crescem com ritmos diferentes e têm donos diferentes.

| Entidade   | Chave           | Campos principais                                                                                                                                                                                                                                       | Dono        |
|------------|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| Tenant     | `tenant_id`     | nome, plano, kms_key_id, parent_tenant (sub-dealer)                                                                                                                                                                                                     | Billing     |
| User       | `user_id`       | tenant_id, papel (owner, tuner, viewer), OIDC subject                                                                                                                                                                                                   | Gateway     |
| Project    | `project_id`    | tenant_id, veículo (VIN opcional), ecu_family, software_version, status                                                                                                                                                                                 | Projects    |
| Artifact   | `artifact_id`   | project_id, sha256, tamanho, **origin** (obd_read, bench_read, boot_read, virtual_read, file_service), **dump_kind** (full, partial, maps_only), **memories\[\]** (memory_id, base_address, size), original ou derived, parent_artifact, retention_lock | Projects    |
| Patch      | `patch_hash`    | Imutável, endereçado pelo hash do conteúdo: **memory_id**, offset, length, before_bytes, after_bytes. Metadados fora do hash: created_in_version (rastreio), map_id, author, ts                                                                         | Projects    |
| Version    | `version_id`    | project_id, parent_version, **lista completa** e canônica de patch_hash (materializar nunca percorre parent_version), overlaps\[\], plugin_versions, layout_hash, label                                                                                 | Projects    |
| EcuFamily  | `family_id`     | fabricante, nome (MED17.5.21, EDC17C46), plugin_id, layout_schema                                                                                                                                                                                       | Definitions |
| Definition | `definition_id` | family_id, software_version pattern, lista de MapDef, origem, confiança                                                                                                                                                                                 | Definitions |
| MapDef     | `mapdef_id`     | definition_id, nome, categoria, offset, dims, tipo de dado, fator, unidade, eixos                                                                                                                                                                       | Definitions |
| MapPack    | `mappack_id`    | tenant_id (ou público), family_id, lista de definition_id, versão semântica, licença                                                                                                                                                                    | Definitions |
| Event      | `event_id`      | tenant_id, project_id, tipo, payload, actor, ts, **prev_hash, hash = sha256(JCS(evento sem hash))**: cadeia por tenant verificável fora do banco, com o head ancorado diariamente em local externo (append-only, particionado por mês)                  | Audit       |
| Job        | `job_id`        | tipo, artifact_id, status, plugin_version, tentativas, resultado_ref                                                                                                                                                                                    | Workers     |

### Decisões de modelagem

- `Patch.before_bytes` existe para detectar conflito: se o original mudou ou dois tuners editaram o mesmo range, o `before` não bate e o sistema recusa.
- `Definition` é desacoplada de `Project`: atualizar o map pack não altera projetos antigos silenciosamente.
- Binários ficam fora do Postgres. O banco guarda só hash, tamanho e caminho; o object store é a fonte de verdade.
- `Event` é a única tabela sem update ou delete, inclusive para admin; como permissão de banco não é verificável de fora, a cadeia de hashes é o que prova que nada foi removido.
- Um `Artifact` com `origin = virtual_read` ou `file_service` não é evidência do que está no carro; o relatório diz isso e o registro de hashes stock (seção Revisão) é consultado para dizer se o arquivo é de fábrica ou já modificado.
- `MapDef.dtype` é completo: int8/16/32, uint, float32, LE/BE, signed, fator e offset, `axis_source` (inline, pointer, shared), para cobrir Siemens/Continental por ponteiro e Delphi/MG1 em float.
- Rótulos têm estado: `proposed` (tuner marcou), `reviewed` (tuner de referência conferiu), `golden` (validado em bancada). Conjunto de validação só usa `reviewed` ou acima.

## Serviços, APIs e SDK de plugins

A API pública é REST com OpenAPI, e tudo que demora mais de 2 s vira job com acompanhamento por SSE. A parte que diferencia o produto, o conhecimento por família de ECU, vive em plugins com interface estável, para que novas famílias entrem sem tocar no core.

### Endpoints principais (v1)

| Método e rota                                 | Função                                          | Modo     |
|-----------------------------------------------|-------------------------------------------------|----------|
| `POST /projects`                              | cria projeto                                    | síncrono |
| `POST /projects/{id}/artifacts/upload-url`    | URL assinada para upload do .bin                | síncrono |
| `POST /projects/{id}/artifacts/{aid}/analyze` | enfileira identify + layout + detect + verify   | job      |
| `GET /jobs/{id}/events`                       | progresso e resultados parciais                 | SSE      |
| `GET /projects/{id}/maps`                     | mapas detectados com score e definição aplicada | síncrono |
| `POST /projects/{id}/versions/{vid}/patches`  | grava patches (valida range e before)           | síncrono |
| `POST /projects/{id}/versions/{vid}/export`   | materializa + checksum + URL assinada           | job      |
| `GET /projects/{id}/versions/{a}/diff/{b}`    | diff por mapa entre duas versões                | síncrono |
| `POST /definitions/import`                    | importa XDF, A2L ou CSV e normaliza             | job      |
| `GET /tenants/{id}/audit`                     | exporta event log (NDJSON)                      | job      |

### Fila e workers

- Um stream por tipo de job (`analyze`, `checksum`, `export`), consumer group por tipo, ack explícito, redelivery com backoff. Jobs são idempotentes por `(artifact_id, plugin_version, tipo)`.
- Workers em Python (numpy para a heurística, `struct` e `numpy.frombuffer` para bytes). Um pod por tipo de job, HPA pelo tamanho da fila.
- Resultado de job grava no object store e publica evento; a API só lê o evento.

### SDK de plugins por família de ECU

Cada família implementa a mesma interface em Python; o core carrega os plugins por entry point e fixa a versão usada em cada job.

    class EcuPlugin(Protocol):
        family: str                      # ex. "bosch.med17"
        version: str                     # semver, gravada em cada job

        # Dump = {dump_kind: bench_full | boot_full | obd_full | obd_partial | virtual,
        #         memories: dict[memory_id, bytes]}   # PFlash, DFlash, EEPROM externa...
        def identify(self, dump: Dump) -> Identification | None: ...
        # Identification = {hw_id, sw_id, mcu, checksum_variant_id, memories_present, base_address?}
        def layout(self, ident: Identification, dump_kind: DumpKind) -> MemoryLayout: ...
        def checksums(self, ident: Identification) -> list[ChecksumRegion]: ...
        # ChecksumRegion.kind = recalculable | signed
        def verify(self, dump: Dump, ident: Identification) -> VerifyReport: ...
        # VerifyReport.status = ok | fail | bypassed | signature_unverifiable | not_applicable
        def checksum_patches(self, dump: Dump, ident: Identification) -> list[Patch]: ...
        def hints(self, ident: Identification) -> list[MapHint]: ...   # offsets prováveis

- A entrada é um **conjunto de memórias**, não um blob: MED17 em TriCore tem PFlash e DFlash (onde ficam VIN, immo e contadores); Marelli IAW e Delphi MT têm EEPROM 95xxx externa; TCU DQ200 traz flash e EEPROM. Leitura OBD devolve só a flash, às vezes parcial, e em várias MED17.5 VAG o Flex faz *virtual read* (arquivo casado pelo SW ID, não bytes da ECU). `layout` recebe `dump_kind` e descreve só as memórias presentes; as ausentes são `unknown`, nunca `calibration`. `verify` em `virtual` devolve `not_applicable`, nunca verde.
- `checksum_patches` substitui o antigo `fix_checksums(bytearray)`: o plugin nunca recebe um buffer mutável. Ele devolve patches e o kernel os aplica, rejeitando o conjunto inteiro se um byte cair fora de região `checksum`. Localidade é imposta pelo kernel, não confiada ao plugin. Para região `signed` (MG1/MD1, Simos18, SIM2K-25x e Denso recentes, com assinatura RSA) devolve lista vazia e `verify` devolve `signature_unverifiable`; o gate exporta só com `alerta`.
- `verify` devolve `bypassed`, não `fail`, para arquivos em que a rotina de verificação foi patchada por outra ferramenta ("checksum off"): é o caso mais comum em arquivo de file service, e dizer "inválido" para um arquivo que liga o carro destrói a credibilidade da auditoria.
- `identify` é função apenas do `Dump`; para parcial devolve `base_address` ou `None`; discrimina ECUs com mesmo `sw_id` e variante de checksum diferente (TC1766 vs TC1797). Extrai VIN e serial, quando presentes, para o pipeline de anonimização.
- `MemoryLayout` é `(memory_id, base_address, regiões)` por memória. Toda região não classificada explicitamente como `calibration` ou `checksum` é `protected`; VIN, immo, coding e contadores de flash são `protected` e nomeados. TPROT não é região: é seed-key do flash OBD, tratado como *flag de proteção detectada*; o plugin nunca a desliga. O plugin declara `pii_in_flash` por família: em MED17/EDC17 o VIN costuma estar na DFlash/EEPROM, então a flash de calibração pode ser anonimizada; Marelli e Delphi, verificar caso a caso.
- Para o grosso das variantes, o checksum é **declarativo**: um descritor interpretado pelo core com `algorithm` (CRC32, soma16/32, XOR, polinômio), `ranges` fixos ou `ranges_from_table` (ponteiros de bloco dentro do arquivo), `init`, `xor_out`, `skip_self` (exclui a própria palavra) e `chain` (checksum de checksums). Cobre Continental SID2xx/SIM2K antigas, Delphi MT, Marelli e boa parte de MED17/EDC17. Plugin em Python só para o exótico. Dupla implementação é feita uma vez, no interpretador.
- `hints` é opcional e alimenta o detector com offsets prováveis para aquela versão de software.
- Plugins são testados contra um corpus de dumps rotulados com golden files: identify, verify e checksum_patches precisam reproduzir o hash esperado antes de o plugin ser publicado.
- Ordem sugerida: Bosch MED17/EDC17 (maior volume), Magneti Marelli IAW 8GMF/9GF (Fiat), ACDelco E8x (GM) e Kefico/SIM2K (Hyundai), depois TCUs (DQ200/DQ250, ZF8HP).

## Infraestrutura e operação

O inventário abaixo é o **alvo v2+**, uma ADR por linha quando houver tenant pagante. O MVP e a v1 rodam em bem menos, e cada camada com um dono claro. A escolha de nuvem é secundária; o desenho evita lock-in nas partes caras de trocar (fila, storage, segredos).

**Infra do MVP e da v1 (decisão v7):** um VPS; `docker compose` com Caddy, FastAPI, um worker, Postgres e NATS; object store externo com versionamento (B2 ou R2, região brasileira quando houver dado pessoal); segredos com SOPS + age; Grafana Cloud free para métricas e logs. Backup diário `pg_dump` para o bucket (RPO 24 h, RTO manual 4 h). Vault, Keycloak, OpenFGA, Temporal, Linkerd, Karpenter, OpenSearch, Argo CD, Terragrunt, PagerDuty, Lago, Litmus e "RPO 0 cross-region" ficam na tabela como alvo, não como plano.

### Inventário completo de componentes (alvo v2+)

| Camada          | Componente                 | Escolha padrão                      | Alternativa          | Observação                                                                 |
|-----------------|----------------------------|-------------------------------------|----------------------|----------------------------------------------------------------------------|
| Borda           | CDN + WAF                  | Cloudflare                          | AWS CloudFront + WAF | Bloqueia scraping de map packs, rate limit por tenant na borda             |
| Borda           | API Gateway / ingress      | Envoy Gateway ou Kong               | NGINX Ingress        | Auth JWT, quotas, request ID, mTLS interno                                 |
| Identidade      | IdP                        | Keycloak                            | Auth0, Zitadel       | OIDC, MFA obrigatório para owner, SSO na fase enterprise                   |
| Identidade      | Autorização                | OpenFGA ou Cerbos                   | Casbin               | Relações tenant → sub-dealer → projeto fora do código de negócio           |
| Aplicação       | API                        | FastAPI (Python) ou Kotlin + Spring | Go                   | Mesma linguagem dos workers reduz atrito nos modelos de dados              |
| Aplicação       | Editor web                 | React + WebGL (regl ou three.js)    | Svelte               | Mapa 16×16 a 32×32 em 60 fps; estado local com CRDT (Yjs) para offline     |
| Aplicação       | Desktop (fase 2)           | Tauri                               | Electron             | Oficinas com internet ruim; mesmo bundle da web                            |
| Assíncrono      | Fila                       | NATS JetStream                      | RabbitMQ, SQS        | Streams por tipo de job, dedupe por chave, replay para reprocessar         |
| Assíncrono      | Orquestração de workflows  | Temporal                            | Argo Workflows       | Pipeline analyze→detect→verify com retries e histórico                     |
| Assíncrono      | Agendador                  | Kubernetes CronJob                  | Temporal schedules   | Limpeza, relatórios de billing                                             |
| Dados           | Banco relacional           | PostgreSQL 16 (CloudNativePG)       | Aurora Postgres      | RLS por tenant, particionamento de Event por mês                           |
| Dados           | Object store               | S3 (ou MinIO self-host)             | GCS, R2              | Bucket por ambiente, prefixo por tenant, Object Lock (WORM) nos originais  |
| Dados           | Cache                      | Redis (Valkey)                      | Dragonfly            | Sessões, resultado de análise quente, locks de edição                      |
| Dados           | Busca                      | OpenSearch                          | Meilisearch          | Busca em definições e map packs por família, versão, nome de mapa          |
| Dados           | Migrations                 | Alembic ou Flyway                   | Atlas                | Sempre compatível com a versão anterior (expand/contract)                  |
| Segredos        | Cofre                      | Vault ou External Secrets + KMS     | Infisical            | Chave KMS por tenant para envelope encryption                              |
| Plataforma      | Cluster                    | EKS/GKE com Karpenter               | k3s em bare metal    | Node pool separado para workers com CPU alta                               |
| Plataforma      | GitOps                     | Argo CD                             | Flux                 | Todo deploy é um commit; rollback é um revert                              |
| Plataforma      | IaC                        | Terraform + Terragrunt              | Pulumi               | Módulos por ambiente; estado remoto com lock                               |
| Plataforma      | Service mesh               | Linkerd                             | Istio                | mTLS automático, retries e timeouts fora do código                         |
| Plataforma      | Política                   | Kyverno ou OPA Gatekeeper           | —                    | Sem imagem não assinada, sem pod root, sem bucket público                  |
| Entrega         | CI                         | GitHub Actions                      | GitLab CI            | Testes, SAST, build, assinatura com cosign, SBOM com syft                  |
| Entrega         | Registro de imagens        | GHCR ou ECR                         | Harbor               | Scan com Trivy no push                                                     |
| Entrega         | Feature flags              | Unleash ou OpenFeature + flagd      | LaunchDarkly         | Liberar família de ECU por tenant antes do GA                              |
| Observabilidade | Métricas                   | Prometheus + Grafana                | Datadog              | SLOs por endpoint e por tipo de job                                        |
| Observabilidade | Logs                       | Loki                                | OpenSearch           | Logs estruturados com tenant_id e request_id; nunca logar bytes de binário |
| Observabilidade | Tracing                    | OpenTelemetry → Tempo               | Jaeger               | Trace atravessa API → fila → worker                                        |
| Observabilidade | Erros                      | Sentry                              | GlitchTip            | Front e back, com release tagueada                                         |
| Observabilidade | Alertas e on-call          | Alertmanager → PagerDuty            | Grafana OnCall       | Runbook por alerta                                                         |
| Observabilidade | Status page                | Instatus                            | Statuspage           | Comunicação de incidente ao cliente                                        |
| Negócio         | Billing                    | Stripe Billing + Lago               | Chargebee            | Créditos por arquivo, assinatura por assento, sub-dealer com repasse       |
| Negócio         | Analytics de produto       | PostHog                             | Mixpanel             | Funil upload → análise → export, por família                               |
| Negócio         | Suporte                    | Intercom ou Plain                   | Zendesk              | Contexto do projeto anexado ao ticket                                      |
| Negócio         | Documentação e API pública | Docusaurus + Redocly                | Mintlify             | Portal de desenvolvedor para o SDK de plugins                              |

### Ambientes e promoção

- `dev` (efêmero por PR, Argo CD ApplicationSet), `staging` (cópia anonimizada de dados), `prod`. Promoção por tag de imagem, nunca por rebuild.
- Deploy canário por tenant: feature flag libera plugin novo para 5% dos tenants, métrica de taxa de correção manual decide o avanço.

### Resiliência e continuidade

- RPO 15 min para Postgres (WAL contínuo para object store), RPO 0 para binários (versionamento + replicação cross-region).
- RTO 1 h: restore de cluster via GitOps + restore de banco testado mensalmente em staging (game day).
- Fila com retenção de 7 dias: reprocessar jobs após incidente sem perda.
- Backups com retenção 35 dias, imutáveis, em conta separada.

### Boas práticas que valem como regra de engenharia

- Twelve-factor para serviços; configuração só por variável de ambiente e segredos por cofre.
- Contratos de API versionados (`/v1`), mudanças incompatíveis só com nova versão e depreciação de 6 meses.
- Testes: unitários nos plugins com golden files, contrato (Schemathesis sobre a OpenAPI), carga (k6) a cada release, caos trimestral (Litmus) em staging.
- ADRs no repositório para cada escolha desta tabela; esta página é a ADR-000.
- Orçamento de erro por SLO: se o SLO de export (99,9% de sucesso) estourar, a release para e o time só faz confiabilidade.

## Segurança e conformidade

O ativo mais valioso da plataforma são os binários dos clientes e os map packs acumulados; o maior risco regulatório é a parte de emissões. Segurança aqui tem três frentes: proteger o dado, proteger o produto contra pirataria e manter o produto fora do terreno de defeat device.

### Proteção dos binários e dos dados

| Controle                 | Implementação                                                                                                                                          |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| Criptografia em repouso  | Envelope encryption: chave de dados por artefato, encapsulada por chave KMS por tenant; revogar a chave do tenant apaga tudo dele                      |
| Criptografia em trânsito | TLS 1.3 na borda, mTLS entre serviços via mesh                                                                                                         |
| Isolamento               | RLS no Postgres com tenant_id por sessão; prefixo de bucket por tenant com política IAM que nega cross-prefix; namespaces e NetworkPolicy por ambiente |
| Acesso de operadores     | Sem acesso humano a binário em produção; break-glass com aprovação de dois e trilha em Event                                                           |
| Upload                   | Antivírus e validação de tamanho e tipo antes de aceitar; binário nunca é executado, só lido                                                           |
| Retenção                 | Originais com Object Lock pelo prazo do contrato; derivados expiram conforme o plano; exclusão a pedido em 30 dias com certificado de destruição       |
| Logs                     | Nunca contêm bytes de binário, VIN ou e-mail; mascaramento no SDK de logging                                                                           |

### Segurança da aplicação (AppSec)

- OWASP ASVS nível 2 como baseline; SAST (Semgrep), SCA (Dependabot + Trivy), DAST (ZAP) na pipeline, bloqueando merge em crítico.
- Supply chain: imagens assinadas (cosign), SBOM por release, admission controller recusa imagem não assinada; plugins de terceiros rodam em sandbox (gVisor) com CPU, memória e sem rede.
- Pentest externo anual e bug bounty privado a partir da v1.
- Modelo de ameaças por quadrimestre (STRIDE sobre o diagrama de componentes).

### Licenciamento e antipirataria

- Licença por assento ligada ao IdP; créditos por arquivo debitados no export, nunca no upload.
- Map packs com metadados assinados por tenant e, se necessário, mapas-isca; a perturbação de offsets e fatores foi cortada (quebra o mapa ou induz edição errada).
- Export de definições em XDF/A2L só para o próprio tenant, com metadados assinados; limite diário por plano.
- Cliente desktop com verificação de licença online a cada 72 h e carência offline; sem DRM pesado, que o mercado odeia e crackeia em semanas.

### Conformidade regulatória

- **Emissões e regulatório automotivo.** O produto não oferece, documenta nem oculta funções de desativação de DPF, EGR, SCR, catalisador, lambda ou DTC de emissão. Regiões dessas funções são `protected` no `MemoryLayout` e o core recusa patch nelas. Base brasileira: CTB arts. 98 e 230, VII (alteração de característica do veículo pode exigir autorização), Lei 8.723/1993 e resoluções CONAMA do PROCONVE; aumento de potência altera emissões mesmo sem delete e pode reprovar em inspeção ambiental onde houver. Termo de uso e relatório de export informam isso. Verificar resolução CONTRAN vigente. O caso COBB/EPA nos EUA fica como referência de risco de mercado, não como base legal.
- **LGPD.** VIN é dado pessoal (art. 5º, I) quando vinculável ao proprietário via RENAVAM, nota ou OS; imobilizador e odômetro no dump também. Prestação do serviço: execução de contrato (art. 7º, V), com a **oficina como controladora e a plataforma como operadora**, com contrato de operador (art. 39). Corpus: a plataforma é controladora com finalidade própria; preferir anonimização verificável (art. 12: remover VIN, serial da ECU, immo e odômetro, com procedimento testado, não só "VIN opcional") e, onde não for possível, legítimo interesse com teste de balanceamento (LIA) registrado, ou consentimento colhido diretamente do titular (dono do carro), específico e destacado (art. 8º, §4º). "Opt-out" não é categoria da LGPD. Encarregado nomeado ou canal público equivalente se enquadrado como pequeno porte (Res. CD/ANPD 2/2022); RIPD do pipeline de ingestão e corpus (art. 38); registro de operações (art. 37). Retenção definida para o Event log (contém dados de funcionários das oficinas).
- **Exclusão e retenção.** Não existe prazo de 30 dias na LGPD. Exclusão por destruição da chave do artefato, incluindo cópias em backup e chaves em custódia; retenção do original enquanto houver obrigação legal ou litígio em curso (art. 16, I e III), documentada no RIPD. Object Lock em modo governance, nunca compliance.
- **Transferência internacional.** Object store ou KMS fora do Brasil é transferência internacional (art. 33): só com cláusulas-padrão da ANPD (Res. CD/ANPD 19/2024) assinadas com o provedor e listadas na política de privacidade. No MVP, região brasileira. GDPR aplica-se por oferta a residentes na UE, não pela nacionalidade do tenant.
- **SOC 2 Tipo II** como meta da v2; os controles acima já são desenhados para o mapeamento.
- **Propriedade intelectual.** Firmware é programa de computador (Lei 9.609): armazenar para prestar o serviço é defensável; copiar para corpus de teste é reprodução não coberta pelo art. 6º, então o corpus só com dumps anonimizados, uso interno de teste, sem redistribuição, nunca em repositório público. A2L/DAMOS vazados: hospedar e processar conhecendo a origem pode caracterizar concorrência desleal (Lei 9.279, art. 195, XI), e "privado ao tenant" não neutraliza; definições sem licença verificável não são hospedadas, só referenciadas localmente pelo cliente. Verificar com advogado a exceção de interoperabilidade (Lei 9.609, art. 6º, IV) para engenharia reversa de checksum. "DMCA" é procedimento do GitHub, não lei brasileira.
- **Anticircunvenção (Lei 9.610, art. 107).** Mira dispositivos que impedem cópia; checksum é integridade, então recálculo provavelmente não é circunvenção. TPROT e assinatura RSA são medidas técnicas: o plugin nunca as desliga nem patcha rotina de verificação. Verificar.
- **Responsabilidade civil.** Termo de ciência do dono do carro não exclui responsabilidade objetiva (CDC arts. 12, 14, 25 e 51, I); serve como prova de informação adequada (art. 6º, III). A plataforma integra a cadeia de fornecimento (art. 7º, par. único) e a própria oficina pode invocar o CDC como destinatária final (verificar). Pacote mínimo: termo de informação ao dono do carro (riscos, perda de garantia, emissões, irregularidade administrativa), contrato B2B com a oficina com indenização e limite de responsabilidade, e cotação de seguro de RC profissional/E&O antes do piloto.

### Resposta a incidentes

- Severidades S1 a S4 com SLA de comunicação (S1: cliente avisado em 1 h, status page em 30 min). Vazamento de binário com VIN é incidente de dados pessoais: comunicação à ANPD e aos titulares em até 3 dias úteis quando houver risco relevante (art. 48; Res. CD/ANPD 15/2024), com a oficina como controladora no playbook.
- Playbooks para vazamento de binário, comprometimento de credencial e corrupção de checksum em export.
- Post-mortem sem culpa em até 5 dias úteis; ações viram itens com dono e prazo.

## Roadmap por fases

Cada fase só começa quando o gate da anterior é medido, não quando o prazo chega. O MVP é deliberadamente single-tenant e com uma família de ECU: o risco técnico está em exportar um arquivo que liga o carro, não em escalar.

*(diagrama: ver o artefato HTML do ADR)*
*roadmap · 3 fases, 3 gates*

Os prazos da Fase 0 são para uma pessoa mais o tuner de referência em meio período; Fases 1 e 2 assumem 3 a 5 pessoas e são ficção até haver receita. O gate decide o avanço, o mês não.

**Sobre ML (Fase 2, não antes).** A detecção no MVP e na v1 é heurística mais definições importadas. Cada confirmação ou correção do tuner no editor vira rótulo; é esse uso que cria o dataset, não o contrário. Um modelo (gradient boosting sobre features do bloco, depois algo maior se valer) só entra quando superar a heurística em precisão por família no conjunto de validação, com rollback automático se a taxa de correção manual subir. Nada de GPU, feature store ou registro de modelos no inventário até lá.

## Riscos e decisões em aberto

O risco que mata o projeto não é técnico: é não ter corpus de dumps rotulados e não ter quem conheça as ECUs por dentro. A arquitetura mitiga, mas não resolve.

| Risco                                                                                | Probabilidade       | Impacto            | Mitigação                                                                                                       |
|--------------------------------------------------------------------------------------|---------------------|--------------------|-----------------------------------------------------------------------------------------------------------------|
| Sem dataset para validar plugins                                                     | Alta                | Alto               | Parceria com 5 oficinas piloto em troca de licença vitalícia; cada correção no editor vira rótulo               |
| Falta de especialista em ECU no time                                                 | Alta                | Alto               | Contratar tuner experiente meio período desde o mês 1; cursos oficiais dos fabricantes de ferramenta            |
| Checksum errado trava carro de cliente                                               | Média               | Crítico            | Golden files por família, verify antes e depois do export, bloqueio de export sem verify verde                  |
| Mercado dominado por ecossistemas fechados (Alientech, Magicmotorsport, EVC)         | Alta                | Médio              | Diferenciar em famílias nacionais e em fluxo, não em cobertura total; não competir em hardware                  |
| Pressão de clientes por funções de delete                                            | Alta                | Alto (regulatório) | Decisão de produto fechada e pública; região protegida no layout; termos de uso                                 |
| Vazamento de map pack                                                                | Média               | Médio              | Watermark por tenant, limite de export, revogação                                                               |
| Bancada virtual dá falsa segurança                                                   | Média               | Alto               | Veredito sempre mostra o que o nível testou e o que não testou; nível 1 nunca é vendido como "testado em motor" |
| Carros novos com ECU assinada (RSA, boot criptografado)                              | Alta no longo prazo | Alto               | Foco em frota 2008 a 2020 no MVP; acompanhar o que os fabricantes de hardware desbloqueiam                      |
| File service bloqueia ou copia: ele é o fornecedor da oficina e tem o relacionamento | Alta                | Alto               | Vender auditoria ao file service como selo de qualidade antes de vender contra ele                              |
| Concorrente adiciona diff nativo (StageX com "compare with original" numa release)   | Alta                | Crítico            | Registro de hashes stock, verify independente e PDF para ordem de serviço são defensáveis; diff sozinho não é   |
| Container do Flex muda (formato, criptografia, termo de uso)                         | Média               | Alto               | Aceitar `.bin` cru como caminho principal; adaptadores de container são periféricos                             |
| Fundador em meio período, com dois contratos ativos e orçamento zero                 | Alta                | Alto               | Marcos por horas disponíveis declaradas, não por semanas de calendário                                          |

### Decisões em aberto

- Linguagem da API: Python (mesma dos workers) ou Kotlin. Recomendação inicial: Python, para compartilhar modelos de dados com os plugins.
- Temporal desde o MVP ou fila simples primeiro. Recomendação: fila simples no MVP, Temporal quando o pipeline tiver mais de 5 estágios.
- Nuvem gerenciada ou bare metal com k3s para controlar custo de storage. Depende do volume médio de dumps por tenant (medir no piloto).
- Modelo de preço: crédito por export, assinatura por assento, ou híbrido. Validar com as oficinas piloto.
- Mercado-alvo inicial: só Brasil (famílias Fiat/VW/GM nacionais) ou já LATAM.

## Comparativo com líderes de mercado

Cinco analistas, cada um num tópico, confrontaram o ADR com WinOLS (EVC), ECM Titanium e KESS3 (Alientech), StageX e Flex (Magicmotorsport), Autotuner, Swiftec e HP Tuners, com busca nas páginas oficiais e de revendedores em outubro de 2026. Achado central: **nenhum líder audita arquivo de terceiro, nenhum bloqueia arquivo implausível antes de gravar, e nenhum liga datalog ao hash do arquivo gravado**. O gate, o verify independente e a proveniência não têm equivalente. As lacunas do ADR são de produto em volta disso, não do núcleo.

### Onde o ADR está à frente (consenso dos cinco)

- **Verify independente com semântica honesta** (`bypassed`, `signature_unverifiable`, `not_applicable`): HP Tuners só diz "invalid checksum, volte ao stock"; WinOLS e ECM corrigem; StageX nem corrige. Ninguém diz ao cliente que a rotina de verificação do arquivo de terceiro foi patchada.
- **Proveniência criptográfica e reprodutível**: hash por patch, cadeia de eventos verificável fora do banco, versão de plugin e build no export. Os líderes são caixa-preta; WinOLS oferece o oposto (ocultar o dono no export).
- **Gate obrigatório, fail-closed, com disclaimer honesto**: o mercado corrige checksum e para; o texto "não verifica combinação entre mapas nem o motor real" é mais honesto que qualquer material oficial lido.
- **Datalog ligado à versão e ao hash**: no KESS3 o log vai para a nuvem com nome livre; no HP Tuners é arquivo solto.
- **Corpus com estados de rótulo** (`proposed → reviewed → golden`) e ML só com gate de precisão: StageX vende "IA" sem critério verificável.
- **Posição regulatória explícita**: Swiftec vende DPF/EGR/AdBlue como núcleo e StageX vende DTC removal por coins; o ADR é defensável onde os líderes carregam passivo.

### Lacunas e melhorias adotadas, por tópico

| Tópico                                    | O que o líder faz                                                                                                                                                                                                                                                | Lacuna no ADR                                                                            | Melhoria adotada (entra na fase indicada)                                                                                                                                                                                                                                                     |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Detecção: mapa potencial                  | WinOLS busca em background segundos após criar o projeto e lista "potential maps" com preview 3D e hexdump sincronizado; "Bosch Recognition" por padrão de cabeçalho                                                                                             | Candidato heurístico não é um estado do editor; sem detector por cabeçalho de fabricante | Candidatos nascem como `MapDef{state: potential}` listados à parte; detector `BoschHeaderDetector` plugável antes de qualquer ML; editor com hexdump sincronizado e realce de `potential` (Fase 0 a 1)                                                                                        |
| Detecção: um pack, várias versões         | StageX: "um único map pack trabalha em qualquer versão de software da mesma ECU"                                                                                                                                                                                 | Aplicação a "irmão próximo" por offset não descreve realinhamento                        | `Identify` consulta índice global `sw_id → Definition` e devolve `definition_match: exact | sibling | none`; para `sibling`, cada `MapDef` é realinhado procurando os eixos conhecidos numa janela ±N KB; só eixos idênticos viram `proposed` (Fase 1)                                        |
| Detecção: importação curada               | WinOLS OLS521 (DAMOS/A2L, €785) com filtros para 2.000 a 10.000 mapas                                                                                                                                                                                            | Importar 5.000 mapas sem triagem replica o problema; DAMOS fora do endpoint              | Import aceita DAMOS; gera `MapDef{state: imported}` e uma view curada por categoria é o que o editor mostra por padrão (Fase 1)                                                                                                                                                               |
| Checksum: descobrir cobertura             | WinOLS testa todos os módulos online contra o projeto e diz qual se aplica; vende por "pontos" (2 = €300, 50 = €4.990, revendedor, verificar)                                                                                                                    | Sem "qual plugin cobre este arquivo"                                                     | Endpoint `probe`: roda `identify` de todos os plugins e reporta variante coberta ou não; cobrança por família ou variante, não por assento (Fase 1)                                                                                                                                           |
| Checksum: estratégias que faltam          | WinOLS em EDC16/17 ajusta um valor de compensação no fim da área de mapas em vez de recalcular; sincroniza blocos espelhados em Bosch truck                                                                                                                      | Descritor declarativo não cobre compensação nem bloco espelhado                          | `strategy: compensate` e `mirror_block` no descritor; ambos em região `checksum`, invariante 9 segue valendo (Fase 0)                                                                                                                                                                         |
| Checksum: ECU assinada                    | Flex, Autotuner e KESS3 gravam MG1/MD1 em bench; a ferramenta resolve a assinatura (como, não publicado; verificar)                                                                                                                                              | ADR declara `signed` corretamente mas não dá caminho ao cliente                          | Export "unsigned" com confirmação registrada de que a ferramenta assina; resultado da gravação vai no `oracle:` (Fase 2)                                                                                                                                                                      |
| Ferramentas: arquivos de slave            | Autotuner slave: arquivo criptografado, time lock de 24 h, API do master para decriptar; KESS3 slave preso a um master; file-service.com integra via API                                                                                                         | ADR assume `.bin` cru; arquivo de slave nunca entra                                      | Camada de ingestão com adaptadores por ferramenta (API Autotuner Master, zip de file service, FRF/VBF); slave fica fora do escopo e vira pré-requisito documentado; `origin = file_service` guarda metadados do container (Fase 1)                                                            |
| Ferramentas: manifesto de compatibilidade | Accessport só lista mapas do veículo identificado; KESS3 identifica antes de escrever; bloqueio explícito de arquivo incompatível não documentado (verificar)                                                                                                    | Export não carrega manifesto que a ferramenta possa conferir                             | Export com manifesto (família, `sw_id`, hash) que um plugin de hardware confira antes de escrever (Fase 2)                                                                                                                                                                                    |
| Fluxo: projeto como contêiner             | WinOLS guarda original, cliente, placa, lista pesquisável, exporta xlsx                                                                                                                                                                                          | `Project` sem cliente, placa, OS nem busca                                               | `customer_ref`, placa e `work_order` no `Project`; `GET /projects?q=`; export CSV (Fase 1)                                                                                                                                                                                                    |
| Fluxo: versões comentadas                 | WinOLS: versões com comentário, "version overview" com mapas tocados, combinar versões                                                                                                                                                                           | `Version` sem nota nem resumo de mapas tocados                                           | `note` obrigatório em `Version`; `GET /versions/{vid}/summary` via `map_id` dos patches; merge = união de patches com conflito por `before` (Fase 1)                                                                                                                                          |
| Fluxo: diff entre projetos                | ECM Titanium 3.0 compara arquivos de veículos diferentes alinhando offsets; HP Tuners compara OS IDs diferentes; WinOLS "accept changes" acha mapa deslocado                                                                                                     | Diff só dentro do mesmo projeto, por mapa                                                | Diff entre quaisquer dois artefatos do tenant, alinhado por `MapDef` (nome e eixos) e por região do layout quando não há definição; ação "importar patches de outra versão" (Fase 0, é o produto de auditoria)                                                                                |
| Fluxo: relatório para o cliente final     | Nenhum líder entrega relatório de auditoria; file-service.com gera PDF de fatura                                                                                                                                                                                 | Relatório de uma página previsto, formato não especificado                               | PDF + JSON com hash e QR; página pública `verify/{report_hash}` que recalcula a cadeia; linguagem leiga: "o que mudou", "integridade", "o que não foi verificado" (Fase 0)                                                                                                                    |
| Fluxo: direitos por projeto               | WinOLS Reseller: direitos por projeto (ver vs exportar binário/mapas), arquivo e chave em servidores separados; StageX slave aplica soluções do master                                                                                                           | Sub-dealer só como tenant filho                                                          | Permissões por `Artifact`/`Version` (`view_diff`, `export_bin`); entregável `sealed` assinado por tenant, sem criptografia proprietária (Fase 1)                                                                                                                                              |
| Fluxo: SLA visível                        | File services publicam tempo de resposta (ex. 60 min); file-service.com mostra horários e ETA                                                                                                                                                                    | Análise \< 30 s, mas sem ETA nem SLA exposto                                             | ETA do job no SSE e SLA no relatório (Fase 1)                                                                                                                                                                                                                                                 |
| Licença: modelo                           | WinOLS €1.034 perpétuo + €98/ano premium; ECM Titanium Full €2.390 ou Credit €890; StageX Plus ≈ €1.900; KESS3 e Flex com renovação anual e perda de protocolos (e, no Flex, da garantia) sem assinatura; HP Tuners US\$ 49,99/crédito preso a VIN + serial + OS | Sem âncora numérica; perpétuo + anual não considerado                                    | Pacote de auditoria perpétuo barato + assinatura anual de definições, corpus e hashes stock; crédito por `(sw_id, hash do VIN)` com re-export do mesmo carro gratuito; estorno automático quando `verify` falha; CLI local sem verificação de licença, o valor pago fica no servidor (Fase 1) |
| Licença: treinamento e canal              | EVC cobra €2.975 a €4.760 por curso WinOLS; Alientech €585 a €2.926; todos vendem por rede de revendedores                                                                                                                                                       | Treinamento tratado como despesa; sem canal                                              | Curso "auditoria de arquivo" com a oficina parceira como instrutora remunerada (resolve a contrapartida); file service como revendedor com margem sobre auditorias indicadas (Fase 1)                                                                                                         |
| Validação: fechar o loop do datalog       | HP Tuners: histogramas 2D/3D por bin, math parameters, "Paste Special" copia o histograma de erro na tabela; MegaLogViewer HD como visor universal                                                                                                               | Datalog antes/depois é só informativo                                                    | "Sugerir patch a partir do bin" (erro de λ vira fator na célula), sempre como `Patch` com `before`; parsers por origem (KESS3, Autotuner, HPT, COBB, MegaLogViewer) para sinais canônicos; export para MegaLogViewer (Fase 1)                                                                 |
| Validação: faixas como dado aberto        | Nenhum líder tem plausibilidade por mapa; KESS3 só min/máx por sinal no datalogger                                                                                                                                                                               | Cobertura de categorias ainda incompleta                                                 | Priorizar categorias pelo volume de edição real do corpus; publicar a tabela de faixas como dado aberto e versionado (Fase 0 a 1)                                                                                                                                                             |
| Validação: HIL acessível                  | MetSim Pro (≈ €5.445) roda ECU na mesa e lê DTC; sem integração com editor                                                                                                                                                                                       | Nível 3 cortado                                                                          | Quando voltar, usar simulador de mercado como executor do roteiro, não HIL próprio (Fase 2+)                                                                                                                                                                                                  |

### O que o mercado resolveu e o ADR aceita

Checksum foi resolvido no hardware de gravação, e os líderes vendem cobertura, não algoritmo. O valor deste produto está no verify, na auditoria e na proveniência; recálculo próprio é add-on para bench, boot e famílias sem suporte na ferramenta. Essa conclusão já estava na seção StageX e os cinco comparadores a confirmaram.

### Fontes do comparativo

- EVC/WinOLS: [software](https://s-web.evc.de/en/product/ols/software), [DAMOS](https://www.evc.de/en/product/ols/damos.asp), [Reseller](https://evc.de/en/product/ols/reseller/info.asp), [what's new](https://www.evc.de/en/download/down_winols_whatsnew.asp), [cursos](https://www.evc.de/it/service/official_training_courses.asp), [FAQ checksum](https://www.evc.de/en/service/q1307.asp)
- Magicmotorsport: [StageX](https://www.magicmotorsport.com/stagex/), [Flex](https://magicmotorsport.com/?p=48384), [renovação Flex](https://viezu.com/shop/magic-motorsport-flex-subscription-renewal)
- Alientech: [KESS3](https://www.alientech-tools.com/en/kess3/), [ECM Titanium Full](https://tuning-shop.com/alientech/ecm-titanium-full-version), [ECM Titanium 3.0](https://viezu.com/?p=49990), [Alientech Suite](https://viezu.com/user-guide-for-alientech-suite-and-kess3-obd), [preços KESS3](https://paramount-performance.com/alientech-kess-3-price-where-to-buy/), [datalog KESS3](https://olsx.lu/en/faq/how-to-use-the-datalog-function-with-your-kess3)
- Autotuner: [tool](https://www.autotuner.com/products/autotuner-tool), [slave files](https://help.autotuner.com/en/articles/2984977-how-to-decrypt-slave-files-and-backup), [integração file-service.com](https://file-service.com/knowledge-base/features/autotuner-integration), [erros comuns](https://tuning-shop.com/blogs/autotuner-mistakes/)
- HP Tuners: [licenças](https://docs.hptuners.com/VCM_Editor/Introduction/Licensing_Vehicles/), [invalid checksum](https://support.hptuners.com/support/solutions/articles/153000064357-reader-upload-invalid-checksum), [math parameters](https://www.hptuners.com/articles/getting-started-with-math-parameters-in-vcm-scanner/), [histogramas](https://www.hpacademy.com/previous-webinars/215-how-to-use-histograms-in-hp-tuners/)
- Outros: [Swiftec](https://viezu.com/blog/swiftec-tuning-software-explained/), [Swiftec preço](https://bds.lt/en/swiftec-full-pack-car-programming-software), [file-service.com](https://file-service.com/the-platform), [COBB datalog](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/571899907/How+To+Datalog), [MetSim Pro](https://bds.lt/en/engine-control-module-diagnostic-and-repair-equipment-metsim-pro), [HP Academy checksum](https://www.hpacademy.com/blog/check-sum-correction-what-how-why/)

Marcados "verificar" pelos analistas: preço unitário de módulo WinOLS (só pacotes em revendedor); como KESS3, Autotuner e Flex tratam assinatura RSA; bloqueio explícito de arquivo incompatível nas ferramentas; formato dos CSV de datalog do KESS3 e Autotuner; modelo de licença do Swiftec; "project history" do ECM Titanium; preços de map pack do StageX em coins.

### Fontes

- [MagicMotorSport StageX, descrição do produto](https://automechanika.messefrankfurt.com/frankfurt/de/ausstellersuche.detail.html/magicmotorsport-srl/mf_1_0015025589_3774404_10000007202401.html)
- [StageX Plus, preço de referência (BDS)](https://bds.lt/en/vehicle-remapping-software-stagex-plus-magicmotorsport)
- [Viezu: ECM Titanium vs WinOLS](https://viezu.com/blog/alientech-ecm-titanium-vs-evc-winols-car-tuning-software/)
- [DOJ: acordo com a COBB Tuning por defeat devices](https://www.justice.gov/archives/opa/pr/united-states-reaches-agreement-cobb-tuning-products-clean-air-act-violations)

