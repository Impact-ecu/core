# Impact · contexto para o Claude (chat e terminal)

Gatilho: **"Retome Impact ECU"** significa retomar este projeto a partir deste arquivo e de `specs/SPEC-000-adr.md`.

## O que é
- Impact é uma plataforma de verificação e recalibração de ECU/TCU automotiva (concorrente de StageX, WinOLS, ECM Titanium), do Luiz (platform engineer, GitHub pessoal `eusouluizlacerda`).
- Organização GitHub `Impact-ecu`. Este repositório é o `core` público (AGPL-3.0). Corpus de dumps e plugins de família ficam em repositórios privados da organização.
- O ADR completo (arquitetura, revisões adversariais, comparativo com líderes) está em `specs/SPEC-000-adr.md`. Os diagramas estão só no artefato HTML original no Claude.
- Há uma oficina parceira, que usa Flex + StageX.

## Decisões fixadas (2026-10-18), não reabrir sem o Luiz
- Confiabilidade é o produto. O núcleo crítico vem primeiro e muito bem feito: kernel de binário (`apply`/`release`, patches imutáveis por hash, diff, 12 invariantes com teste de propriedade), contrato de plugin por família de ECU com suíte de conformidade, gate de verificação (veredito `bloqueia | alerta | sem achados`, fail-closed) e proveniência reprodutível (JCS, cadeia de hashes). Nada de vender antes disso.
- Custo zero no MVP: tudo grátis ou open source, em regime de teste. Qualquer coisa paga é Fase 1 ou posterior.
- Só software: sem hardware ou bancada próprios. O oráculo de checksum é delegado à oficina (ela grava, devolve hash e log de diagnóstico → `golden_field`); `golden_concordant` (duas ferramentas gratuitas concordando) serve para desenvolver, não para lançar plugin.
- Princípios: agnosticidade (fabricante, ferramenta de leitura, formato de definição, nuvem, cliente), imutabilidade do original, determinismo, verificação antes de confiança, o usuário ensina o sistema. ML só em fase posterior, com gate de precisão. Nenhuma função de delete de emissão, nunca; regiões correspondentes são `protected` e o plugin nunca desliga TPROT nem patcha rotina de verificação.
- Primeiro produto: auditoria e verificação de arquivos de terceiros (verify independente com `bypassed`/`signature_unverifiable`/`not_applicable`, diff por mapa, relatório de proveniência em PDF+JSON). Recálculo de checksum é add-on.
- Primeira família: Bosch MED17, por variante de checksum (hardware + método), não por família.
- Negócio e jurídico (contrato com oficina, termo ao dono do carro, seguro) entram só na Fase 1, quando o primeiro arquivo for para carro de terceiro.

## Regras de engenharia do núcleo (resumo; detalhes na SPEC-000)
- `src/core/` é Python puro: sem I/O, rede, subprocess, framework. import-linter garante.
- Entrada é `Dump{dump_kind, memories}` (multi-memória), nunca um blob. `Patch` carrega `memory_id`.
- Nenhum byte de dump neste repositório público: `tests/golden/` só tem hashes + `oracle:`.
- Cobertura 100% com branch, mypy `--strict`, Hypothesis ≥ 2.000 exemplos por invariante, fuzz nos parsers, mutation score ≥ 90% medido no nightly, ratchets em `guardrails/ratchet.json` só sobem.
- Caminhos de fundação (`src/core/kernel`, `gate`, `provenance`, `plugins/_contract.py`, `conformance`, `specs/`, `guardrails/`, `.github/`) só mudam com label `foundation-change`, spec ou ADR no mesmo PR, PR aberto ≥ 24 h desde o último commit.
- Estrutura: `src/core/{kernel,plugins,gate,provenance,definitions,conformance}`, `tests/{properties,golden,fuzz}`, `specs/`, `guardrails/`, `.github/workflows/`.

## Estado e próximos passos
- Fase −1 (descoberta), antes de código do núcleo: acompanhar um serviço inteiro na oficina parceira (ferramenta, formato exportado, se edita ou compra arquivo); fechar o acordo de oráculo; mapear o que a comunidade sabe sobre checksum da MED17 por variante. Critério de saída na SPEC-000.
- Depois: SPEC-001 (kernel), kernel com os 12 invariantes, CLI local, plugin MED17 por variante, gate, auditoria na parceira.
- Pendência de infra: o GitHub App do Claude precisa ser instalado na organização `Impact-ecu` para o Claude do chat conseguir push (hoje só na conta pessoal).
