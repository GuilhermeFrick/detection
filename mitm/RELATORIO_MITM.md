# Relatório: Classificadores MITM — SOME/IP

> **Versão**: labeling por conteúdo (spec Kim 2026) — componentes A/B/C identificadas por service_id/method_id/msg_type, incluindo pacotes com IP forjado.

---

## O que é esse ataque?

O ataque **Man-in-the-Middle (MITM)** em redes SOME/IP posiciona um ou mais nós maliciosos entre um publicador legítimo e os subscribers. O objetivo não é apenas interceptar dados — é substituir o fluxo legítimo por dados forjados enquanto mantém a aparência de operação normal.

Diferente do DoS (que degrada a disponibilidade) e do Fuzzy (que testa vulnerabilidades), o MITM visa a **integridade e confidencialidade** dos dados veiculares. Um atacante pode, por exemplo, substituir notificações do sistema ADAS com dados falsos, induzindo comportamentos errôneos nos sistemas de segurança do veículo.

---

## Dois cenários estudados

### MITM Multi-Attacker (`mitm_multi_attacker.pcap`)

**Dois atacantes coordenados**: `172.18.0.14` (relay) e `172.18.0.15` (SD spoofing).

#### Componente A — Event Relay (atacante .14)

O atacante intercepta o stream de eventos ADAS legítimo (`svc=0x1001`) e o retransmite através de um **serviço proxy próprio** (`svc=0x100B, instance=0x000B`). Os subscribers recebem os dados via este serviço intermediário controlado pelo atacante.

```
Critério de labeling:
  src_ip ∈ {172.18.0.14, 172.18.0.15}
  AND service_id == 0x100B
  AND method_id  == 0x0001
```

#### Componente B — SD Spoofing com IP Forjado (atacante .15)

O atacante envia mensagens SOME/IP-SD com `IP.src = 172.18.0.10` **forjado** (o servidor ADAS legítimo). Isso força os subscribers a desconectarem do serviço legítimo (TTL=0, withdraw).

```
Critério de labeling:
  src_ip == "172.18.0.10"   ← IP FORJADO (não é o atacante real!)
  AND is_sd == True
  AND msg_type == 0x02
```

> **Por que o labeling por IP falha aqui:** o IP de origem é o do servidor legítimo (172.18.0.10), não do atacante. O labeling por IP rotularia esses pacotes como tráfego benigno do servidor — ou pior, rotularia o servidor como atacante. O labeling por conteúdo capta esses ~167k pacotes corretamente pela combinação is_sd + SD withdraw.

#### Componente C — ADAS Injection (impersonação)

O atacante impersona o serviço ADAS legítimo (`svc=0x1001`) enviando notificações forjadas.

```
Critério de labeling:
  src_ip ∈ {172.18.0.14, 172.18.0.15}
  AND service_id == 0x1001
  AND method_id  == 0x0001
```

---

### MITM Single-Attacker (`mitm_single_attacker.pcap`)

**Um único atacante**: `172.18.0.13`.

#### Componente A — SD Withdraw (desconexão do legítimo)

O atacante envia mensagens SOME/IP-SD do tipo withdraw (TTL=0) para forçar os subscribers a abandonarem o servidor ADAS legítimo.

```
Critério de labeling:
  src_ip == "172.18.0.13"
  AND is_sd == True
  AND msg_type == 0x02
```

#### Componente B — ADAS Event Injection (impersonação)

Após o withdraw, o atacante injeta notificações ADAS forjadas passando-se pelo servidor legítimo.

```
Critério de labeling:
  src_ip == "172.18.0.13"
  AND service_id == 0x1001
  AND method_id  == 0x0001
```

---

## Modelo de ameaça comparativo

| Atributo | MITM Multi | MITM Single |
|---|---|---|
| Atacantes | 2 (`172.18.0.14`, `172.18.0.15`) | 1 (`172.18.0.13`) |
| Técnica de desvio | Serviço relay (`svc=0x100B`) | SD Withdraw direto |
| IP Spoofing | Sim (`.15` forja IP=`.10`) | Não |
| Furtividade | Média — serviço relay é detectável | Média — SD withdraw é detectável |
| Impacto | Integridade (dados forjados via relay) | Integridade (dados forjados + disrupção) |

---

## Os dados

| Arquivo | Total parsado | Benigno | MITM (content-label) | % Ataque |
|---|---|---|---|---|
| `benign_traffic.csv` | 2.193.802 | 2.193.802 | 0 | 0% |
| `mitm_multi_attacker.csv` | 2.412.529 | 2.081.624 | **330.905** | 13,7% |
| `mitm_single_attacker.csv` | 2.037.576 | 1.678.203 | **359.373** | 17,6% |

### Dataset consolidado por classificador

| Classificador | Total amostras | Benigno | MITM | Proporção | Treino/Teste |
|---|---|---|---|---|---|
| MITM Multi | 4.606.331 | 4.275.426 (92,8%) | 330.905 (7,2%) | 13:1 | 50/50 |
| MITM Single | 4.231.378 | 3.872.005 (91,5%) | 359.373 (8,5%) | 11:1 | 50/50 |

Desbalanceamento moderado (11–13:1) — muito menor que o DoS (57:1).

---

## As features

Ambos os classificadores usam **12 features** — as 10 do DoS/Fuzzy mais 2 específicas do MITM:

| Feature | Tipo | Relevância MITM |
|---|---|---|
| `f19_is_sd` | Booleano — `service_id=0xFFFF` | **Crítica para MITM Single** (SD Withdraw) |
| `f21_is_relay_service` | Booleano — `service_id=0x100B` | **Crítica para MITM Multi** (relay exclusivo) |
| `f15_someip_payload_len` | Tamanho do payload SOME/IP | Distingue tamanho de mensagens SD vs ADAS |
| `f20_src_service_diversity` | Serviços únicos usados pelo src_ip | Baixa — relay usa service_id fixo |
| `f17_src_packet_rate` | Taxa de pacotes do src_ip | Secundária — MITM não gera flood |
| `f18_src_payload_diversity` | Diversidade de payloads | Secundária |
| demais (f01, f08, f11, f12, f13, f16) | Comportamentais gerais | Quase nulas |

---

## Como cada modelo enxerga o ataque

### MITM Multi — assinatura do relay service

O componente A usa `svc=0x100B` — um service_id inexistente no tráfego legítimo. A feature `f21_is_relay_service` identifica diretamente esse serviço como flag binária. O modelo aprende: *qualquer pacote com service_id=0x100B é ataque*.

O componente B (SD forjado com IP=.10) e o componente C (ADAS injection) são capturados pelo `f15_someip_payload_len` — as mensagens SD withdraw têm tamanho característico diferente do SD legítimo.

### MITM Single — assinatura do SD Withdraw

O componente A usa `is_sd=True` com TTL=0 (withdraw). Como o atacante `.13` envia SD withdraws que não existem no tráfego benigno (ECUs legítimas não retiram serviços de forma abrupta), `f19_is_sd` domina completamente a detecção com 92,9% de importância.

---

## Importância das features

### MITM Multi

| Posição | Feature | Importância |
|---|---|---|
| 1° | `f21_is_relay_service` | **69,7%** |
| 2° | `f15_someip_payload_len` | 28,7% |
| 3° | `f19_is_sd` | 1,1% |
| 4°–12° | demais | < 1% total |

**98,5% da capacidade discriminativa em 2 features.** O relay service (`svc=0x100B`) é praticamente uma assinatura única — não existe no tráfego legítimo.

### MITM Single

| Posição | Feature | Importância |
|---|---|---|
| 1° | `f19_is_sd` | **92,9%** |
| 2° | `f18_src_payload_diversity` | 2,5% |
| 3° | `f17_src_packet_rate` | 2,4% |
| 4°–12° | demais | < 1% total |

**92,9% da capacidade discriminativa em uma única feature.** O SD Withdraw do atacante é tão anômalo que `is_sd=True` quase resolve sozinho — ECUs legítimas não enviam withdraws de forma contínua.

### Comparativo entre os dois MITM

| Feature | MITM Multi | MITM Single | Por quê difere |
|---|---|---|---|
| `f21_is_relay_service` | **69,7%** | 0% | Relay (`svc=0x100B`) só existe no Multi |
| `f19_is_sd` | 1,1% | **92,9%** | Single usa SD Withdraw; Multi usa relay (f21 já basta) |
| `f15_someip_payload_len` | 28,7% | 0,2% | Complementa f21 no Multi; desnecessário no Single |

---

## Resultados

### MITM Multi-Attacker

| Classe | Precision | Recall | F1-Score | Suporte |
|---|---|---|---|---|
| Normal | 0,9998 | 0,9999 | 0,9999 | 2.137.713 |
| MITM | 0,9990 | 0,9979 | **0,9984** | 165.453 |
| **Média macro** | 0,9994 | 0,9989 | **0,9992** | — |

**AUC-ROC: 1,0000**

```
                  Previsto: Normal   Previsto: MITM
Real: Normal        2.137.546              167     ← 167 falsos alarmes
Real: MITM                349          165.104     ← 349 ataques não detectados
```

### MITM Single-Attacker

| Classe | Precision | Recall | F1-Score | Suporte |
|---|---|---|---|---|
| Normal | 0,9999 | 0,9999 | 0,9999 | 1.936.003 |
| MITM | 0,9997 | 0,9992 | **0,9994** | 179.686 |
| **Média macro** | 0,9998 | 0,9996 | **0,9997** | — |

**AUC-ROC: 1,0000**

```
                  Previsto: Normal   Previsto: MITM
Real: Normal        1.935.942               61     ← 61 falsos alarmes
Real: MITM                143          179.543     ← 143 ataques não detectados
```

---

## Interpretação prática

Ambos os classificadores alcançam AUC=1,0000, mas por mecanismos diferentes:

- **MITM Multi** detecta principalmente pelo **serviço relay exclusivo** (`svc=0x100B`) — uma assinatura que qualquer atacante usando a mesma técnica teria, independente do IP.
- **MITM Single** detecta principalmente pelo **comportamento anômalo de SD** (`is_sd=True` persistente de um único IP) — o SD Withdraw repetido não ocorre no tráfego normal.

Ambos são **IP-agnósticos** nas suas features dominantes: detectam o comportamento estrutural do ataque, não o endereço.

### Limitações

| Limitação | MITM Multi | MITM Single |
|---|---|---|
| Relay com service_id diferente de 0x100B | Não detectado por f21 (f15 pode capturar) | N/A |
| SD Withdraw legítimo durante reconfiguração | N/A | Possível falso positivo (FPR=0,003%) |
| Atacante que não usa SD Withdraw | N/A | Não detectado por f19 |
| Split na mesma simulação | Treino e teste da mesma captura — não completamente inédito |

---

## Resumo comparativo — todos os ataques

| Classificador | F1 | FP | FN | Feature dominante | Mecanismo |
|---|---|---|---|---|---|
| DoS | 0,9998 | 0 | 13 | `f15` (58,7%) | Tamanho fixo + ausência de variação |
| Fuzzy | 0,9979 | 330 | 74 | `f08` (51,3%) | Hamming alto (payload aleatório) |
| **MITM Multi** | **0,9984** | **167** | **349** | `f21` (69,7%) | Service relay exclusivo |
| **MITM Single** | **0,9994** | **61** | **143** | `f19` (92,9%) | SD Withdraw anômalo |

> O MITM Single supera o MITM Multi em precisão porque o SD Withdraw é um sinal quase perfeito — enquanto o Multi depende de um serviço relay que, em teoria, poderia ser camuflado usando um service_id legítimo já existente.
