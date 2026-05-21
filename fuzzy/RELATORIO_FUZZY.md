# Relatório: Classificador de Fuzzing — SOME/IP

> **Versão**: labeling por conteúdo (spec Kim 2026) — conteúdo do pacote determina o label, não o IP de origem.

---

## O que é esse ataque?

O ataque de **Protocol Fuzzing** modela um nó malicioso que tenta estressar e confundir a comunicação orientada a serviços enviando mensagens SOME/IP com campos aleatorizados. Diferente do DoS (que usa um único payload repetido a alta taxa), o fuzzing busca:

1. **Inundar o Service Discovery** com ofertas de serviço sintéticas — ID de serviço aleatório, payload randômico — forçando as ECUs a processar e descartar entradas inválidas de SD.
2. **Injetar notificações ADAS com payload completamente aleatório** — mesmo serviço legítimo (`svc=0x1001`), mas o conteúdo de cada pacote é gerado de forma diferente.

O objetivo é aumentar o tráfego de discovery, ampliar o estado armazenado nas ECUs receptoras e criar ambiguidade para sistemas de monitoramento que esperam uma topologia de serviços estável.

---

## Modelo de ameaça

| Atributo | Valor |
|---|---|
| Posição do atacante | Nó interno à rede veicular (in-vehicle) |
| Objetivo | Degradar processamento das ECUs e o Service Discovery |
| Estratégia | Volume + aleatoriedade de conteúdo (não repetição como DoS) |
| IP atacante | `172.18.0.17` (pcap1) / `172.18.0.12` (pcap2, pcap3) |
| PCAPs | `fuzzy_sd_offer_rand_noti(1/2/3).pcap` |

O atacante **não precisa conhecer a topologia de serviços** — os campos são aleatorizados. Isso o torna mais difícil de detectar por listas de controle de acesso mas com assinatura comportamental distinta (alta variação de payload).

---

## Componentes do ataque

### Componente A — SD OfferService Flooding (`is_sd = True`)

Mensagens SOME/IP-SD enviadas com campos de Service Discovery (`service_id = 0xFFFF`, `method_id = 0x8100`), carregando entradas do tipo `OfferService` com identificadores de serviço aleatórios. Cada pacote tem **payload de 1332 bytes** (tamanho fixo do SD), mas o conteúdo varia completamente entre pacotes.

```
Critério de labeling — Componente A:
  src_ip == atacante
  AND is_sd == True        (service_id = 0xFFFF)
  AND msg_type == 0x02     (Notification)
```

### Componente B — ADAS Random Payload Injection

Notificações SOME/IP enviadas ao serviço ADAS real (`svc=0x1001`, `meth=0x0001`) mas com payload gerado aleatoriamente. Diferente do DoS que envia sempre o mesmo payload, aqui cada pacote contém bytes diferentes.

```
Critério de labeling — Componente B:
  src_ip == atacante
  AND service_id == 0x1001
  AND method_id  == 0x0001
  AND msg_type   == 0x02   (Notification)
```

**O label final é a união de A ou B** — qualquer pacote do atacante que satisfaça ao menos uma das condições é marcado como `label=1`.

---

## Contraste com o ataque DoS

| Característica | DoS | Fuzzy |
|---|---|---|
| **Payload** | Sempre o mesmo (repetição) | Completamente aleatório |
| **Serviços alvo** | ADAS (`svc=0x1001`) | SD (`0xFFFF`) + ADAS (`0x1001`) |
| **Hamming entre payloads** | ≈ 0 (idênticos) | Alto (aleatórios) |
| **Diversidade de payload** | ≈ 0 (um único payload) | ≈ 1.0 (todos diferentes) |
| **Taxa de repetição** | Alta (mesmos bytes) | Nula |
| **is_sd** | Nunca | Sim (componente A) |
| **Payload len** | ~20 bytes (notificação ADAS) | **1332 bytes** (SD flood) |

O fuzzing é o **oposto** do DoS em termos de diversidade: o DoS é detectado pela repetição, o fuzzing pela variação extrema.

---

## Os dados

### De onde vêm?

| Arquivo | Atacante | Conteúdo |
|---|---|---|
| `benign_traffic.pcap` | — | Tráfego 100% benigno |
| `fuzzy_sd_offer_rand_noti(1).pcap` | `172.18.0.17` | Normal + fuzzing leve |
| `fuzzy_sd_offer_rand_noti(2).pcap` | `172.18.0.12` | Normal + fuzzing moderado |
| `fuzzy_sd_offer_rand_noti(3).pcap` | `172.18.0.12` | Normal + fuzzing intenso |

### Tamanho e balanço por PCAP (labeling por conteúdo)

| PCAP | Total | Normal | Fuzzy | % Fuzzy |
|---|---|---|---|---|
| benign_traffic | 2.193.802 | 2.193.802 | 0 | 0% |
| fuzzy1 | 1.705.267 | 1.701.445 | 3.822 | 0,2% |
| fuzzy2 | 1.304.154 | 1.268.249 | 35.905 | 2,8% |
| fuzzy3 | 2.223.650 | 2.073.159 | 150.491 | 6,8% |

### Dataset consolidado para treino/teste

| Conjunto | Total | Normal | Fuzzy | Proporção |
|---|---|---|---|---|
| Treino | 3.713.436 | 3.618.327 (97,4%) | 95.109 (2,6%) | **38:1** |
| Teste  | 3.713.437 | 3.618.328 (97,4%) | 95.109 (2,6%) | **38:1** |

O dataset é desbalanceado (**38:1**), mas muito menos severo que a primeira impressão pelo pcap3 (que tem 6,8%) — a diluição vem do arquivo benigno puro que representa metade do dataset total.

---

## As features

O classificador usa **10 features** — 9 compartilhadas com o classificador DoS mais uma feature exclusiva `f19_is_sd`:

| Feature | O que mede | Relevância para Fuzzy |
|---|---|---|
| `f08_someip_payload_change` | Distância de Hamming entre payloads consecutivos | **Alta** — payloads aleatórios têm Hamming máximo |
| `f15_someip_payload_len` | Tamanho do payload SOME/IP | **Alta** — SD flood usa 1332 bytes (característico) |
| `f17_src_packet_rate` | Taxa de pacotes por IP (janela 1000) | **Alta** — volume elevado do flood |
| `f13_payload_repeat_rate` | Fração dos últimos 5 payloads idênticos | **Alta** — zero no fuzzy (sem repetição) |
| `f18_src_payload_diversity` | Payloads únicos / total (janela 1000) | Média — complementa f08 |
| `f16_tcpudp_len` | Tamanho da camada transporte | Baixa |
| `f11_ip_length_change` | Variação tamanho IP | Baixa |
| `f01_ip_time_interval` | Intervalo entre pacotes do fluxo | Baixa |
| `f19_is_sd` | 1 se `service_id = 0xFFFF` (SOME/IP-SD) | Baixa (redundante dado f15) |
| `f12_tcpudp_length_change` | Variação tamanho TCP/UDP | Nula |

---

## Como o modelo enxerga o ataque

Médias das features por classe no conjunto de treino (normalizado 0 a 1):

| Feature | Normal | Fuzzy | Delta |
|---|---|---|---|
| `f08_someip_payload_change` | baixo | **alto** | **+++ (principal sinal)** |
| `f13_payload_repeat_rate` | 0,44 | **≈ 0** | **forte redução** |
| `f15_someip_payload_len` | variado | **1332 bytes (SD)** | **tamanho característico** |
| `f18_src_payload_diversity` | 0,13 | **≈ 1,0** | **diversidade máxima** |
| `f17_src_packet_rate` | baixo | **alto** | volume elevado |
| `f19_is_sd` | ≈ 0 | **1 (comp.A)** | exclusivo do SD flood |

**A assinatura do fuzzing é o inverso do DoS:**
- DoS: mesmo payload repetido → `f08` baixo, `f13` alto, `f18` baixo
- Fuzzy: payload diferente em cada pacote → `f08` alto, `f13` zero, `f18` máximo

---

## Importância das features

| Posição | Feature | Importância |
|---|---|---|
| 1° | `f08_someip_payload_change` | **51,3%** |
| 2° | `f15_someip_payload_len` | 16,4% |
| 3° | `f17_src_packet_rate` | 13,1% |
| 4° | `f13_payload_repeat_rate` | 12,9% |
| 5° | `f18_src_payload_diversity` | 4,0% |
| 6°–10° | demais features | < 1% cada |

**94,7% da capacidade discriminativa está nas 4 primeiras features.** O modelo identifica o fuzzing pela variação extrema de payload (`f08`) combinada com o tamanho característico do SD flood (`f15`) e o volume elevado (`f17`).

A feature `f19_is_sd` tem importância quase nula (0,23%) porque `f15_someip_payload_len = 1332` já captura implicitamente que o pacote é um SD OfferService — a informação é redundante.

### Comparativo DoS vs Fuzzy — o que cada modelo aprendeu

| Feature | Importância (DoS) | Importância (Fuzzy) | Por quê difere |
|---|---|---|---|
| `f08_someip_payload_change` | ~0% | **51,3%** | Fuzzy aleatoriza; DoS repete → Hamming oposto |
| `f15_someip_payload_len` | **58,7%** | 16,4% | Ambos têm payload característico mas por motivos diferentes |
| `f17_src_packet_rate` | 4,7% | 13,1% | Taxa importa mais no Fuzzy pois f08 já domina o DoS |
| `f18_src_payload_diversity` | 32,2% | 4,0% | DoS tem diversidade ~0 (poderoso sinal); Fuzzy tem ~1,0 (normal também pode) |
| `f13_payload_repeat_rate` | — | 12,9% | Distingue Fuzzy (zero repetições) de tráfego normal |

---

## Resultados

### Métricas no conjunto de teste

| Classe | Precision | Recall | F1-Score | Suporte |
|---|---|---|---|---|
| Normal | 1,0000 | 0,9999 | 1,0000 | 3.618.328 |
| Fuzzy | 0,9965 | 0,9992 | **0,9979** | 95.109 |
| **Média macro** | 0,9983 | 0,9996 | **0,9989** | — |

**AUC-ROC: 0,9999**

### Matriz de confusão

```
                  Previsto: Normal   Previsto: Fuzzy
Real: Normal        3.617.998               330     ← 330 falsos alarmes
Real: Fuzzy                74            95.035     ← 74 ataques não detectados
```

De **95.109 pacotes de ataque**, apenas **74 passaram despercebidos** (0,08%).
**330 falsos alarmes** em 3,6 milhões de normais — taxa de 0,009% (1 em cada 11.000).

---

## Interpretação prática

O classificador Fuzzy detecta o ataque pela **variação extrema de payload** (`f08` dominante) e pelo **tamanho característico do SD flood** (`f15`). Isso é IP-agnóstico: se um novo atacante com IP diferente enviar pacotes SD com payload aleatório de 1332 bytes, o modelo detecta sem qualquer ajuste.

### Limitações

| Limitação | Explicação |
|---|---|
| **Fuzzy de baixa taxa** | Um atacante lento com payload aleatório teria `f17` baixo — `f08` ainda sinaliza mas a confiança cai |
| **Fuzzy distribuído** | Se vários IPs cada um com taxa normal enviarem payloads aleatórios, `f17` não dispara |
| **Payload semi-aleatório** | Fuzzing que altera apenas alguns bytes por pacote tem Hamming baixo — similar ao tráfego normal |
| **Split na mesma simulação** | Treino e teste vêm das mesmas 3 simulações — não é um cenário completamente inédito |

---

## Resumo em uma frase

> O modelo detecta fuzzing com F1=0,9979 e apenas 330 falsos alarmes em 3,6 milhões de pacotes normais, identificando que as mensagens do atacante têm payload completamente aleatório em cada pacote (Hamming elevado, diversidade máxima) — assinatura oposta ao DoS, que repete sempre o mesmo conteúdo.
