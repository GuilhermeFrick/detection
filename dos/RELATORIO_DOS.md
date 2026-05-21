# Relatório: Classificador de DoS — SOME/IP

> **Versão**: labeling por conteúdo (spec Kim 2026) — corrigido em relação à versão anterior que usava labeling por IP de origem.

---

## O que é esse ataque?

O ataque de **DoS por inundação de notificações** (Event Notification Flooding) consiste em um nó malicioso dentro da rede veicular que envia uma quantidade absurda de mensagens SOME/IP em um curto intervalo de tempo. O objetivo é **saturar a rede e sobrecarregar as ECUs** que precisam processar cada mensagem recebida.

No dataset do Kim, o atacante (`172.18.0.11`) envia **3.000 NOTIFICATIONS** para o serviço ADAS (`service_id=0x1001`, `method_id=0x0001`) o mais rápido possível — um loop sem pausa — enquanto as outras ECUs continuam se comunicando normalmente.

---

## Critério de labeling

A versão anterior rotulava como ataque **todos** os pacotes com `ip.src == 172.18.0.11`. Isso incluía tráfego legítimo do nó atacante (SD subscriptions, respostas a serviços, etc.), gerando falsos positivos no treino.

A versão correta usa o critério da spec Kim — um pacote é DoS se e somente se:

```
ip.src == 172.18.0.11
AND service_id == 0x1001   (serviço ADAS)
AND method_id  == 0x0001   (event notification)
AND msg_type   == 0x02     (NOTIFICATION)
```

| Versão | Pacotes rotulados como ataque | % do total |
|---|---|---|
| Anterior (por IP) | 306.944 | 16,5% |
| **Atual (por conteúdo)** | **69.393** | **3,7%** |

A diferença (237.551 pacotes) era tráfego legítimo do nó atacante incorretamente rotulado.

---

## Os dados

### De onde vêm?

| Arquivo | Conteúdo |
|---|---|
| `benign_traffic.pcap` | Tráfego normal entre as 9 ECUs — todos os pacotes são benignos |
| `dos_noti_flood.pcap` | Rede operando normalmente **+ atacante gerando flood** — contém pacotes benignos e de ataque |

### Tamanho e balanço

| Conjunto | Total | Normal | DoS | Proporção |
|---|---|---|---|---|
| Treino | 2.029.166 | 1.994.469 (98,3%) | 34.697 (1,7%) | **57,5:1** |
| Teste  | 2.029.166 | 1.994.470 (98,3%) | 34.696 (1,7%) | **57,5:1** |

O dataset é **severamente desbalanceado** — para cada pacote de ataque há 57 normais. Esse é o balanço real do ataque quando rotulado corretamente. O modelo não recebeu compensação explícita por esse desequilíbrio (`scale_pos_weight` padrão).

---

## As features

O classificador usa **9 features** extraídas de cada pacote com base em janelas deslizantes de histórico:

| Feature | O que mede | Como é calculada |
|---|---|---|
| `f01_ip_time_interval` | Intervalo de tempo desde o pacote anterior na mesma sessão | `abs(ts_atual - ts_anterior)` por fluxo |
| `f08_someip_payload_change` | Quanto o payload SOME/IP mudou em relação ao anterior | Distância de Hamming entre payloads consecutivos |
| `f11_ip_length_change` | Variação no tamanho do pacote IP | `abs(len_atual - len_anterior)` |
| `f12_tcpudp_length_change` | Variação no tamanho da camada de transporte | `abs(len_atual - len_anterior)` |
| `f13_payload_repeat_rate` | Fração dos últimos 5 payloads idênticos ao atual | Quantos dos 5 últimos são iguais ao atual |
| `f15_someip_payload_len` | Tamanho do payload da mensagem SOME/IP | Bytes após o header de 16 bytes |
| `f16_tcpudp_len` | Tamanho do segmento de transporte | Bytes da camada UDP/TCP |
| `f17_src_packet_rate` | Taxa de pacotes enviados por esse IP de origem | Pacotes nos últimos 1.000 timestamps / intervalo |
| `f18_src_payload_diversity` | Diversidade de payloads enviados por esse IP | Payloads únicos / total na janela de 1.000 |

---

## Como o modelo enxerga o ataque

Médias das features normalizadas (0 a 1) por classe no treino:

| Feature | Normal | DoS | Delta |
|---|---|---|---|
| `f13_payload_repeat_rate` | 0,436 | **0,976** | **+0,541** |
| `f16_tcpudp_len` | 0,239 | 0,394 | +0,155 |
| `f15_someip_payload_len` | 0,104 | 0,188 | +0,084 |
| `f18_src_payload_diversity` | **0,128** | **0,007** | **−0,121** |
| `f17_src_packet_rate` | 0,037 | 0,038 | +0,001 |
| `f01_ip_time_interval` | 0,003 | 0,000 | −0,003 |
| `f08_someip_payload_change` | 0,008 | 0,000 | −0,008 |

### O que chama atenção:

**`f13_payload_repeat_rate` sobe de 0,436 para 0,976** — o sinal mais intenso numericamente.
O atacante envia 3.000 notificações com o mesmo payload repetidamente: praticamente todos os últimos 5 payloads são idênticos ao atual (rate ≈ 1,0). No tráfego normal esse índice fica em torno de 0,44.

**`f18_src_payload_diversity` cai de 0,128 para 0,007** — confirmação direta do flood.
O atacante envia sempre a mesma notificação ADAS; a janela de 1.000 payloads não tem variedade. No tráfego normal diferentes serviços e dados geram diversidade natural.

**`f15_someip_payload_len`** — as notificações ADAS (`service_id=0x1001`) têm um tamanho de payload específico e consistente, diferente da mistura de tamanhos do tráfego normal.

**`f17_src_packet_rate`** — a diferença de média é ínfima (0,0009) porque a taxa é calculada sobre TODOS os pacotes do IP atacante, incluindo seu tráfego legítimo (SD, subscriptions) que "dilui" a alta taxa do flood nas médias.

---

## Importância das features

| Posição | Feature | Importância |
|---|---|---|
| 1° | `f15_someip_payload_len` | **58,7%** |
| 2° | `f18_src_payload_diversity` | **32,2%** |
| 3° | `f17_src_packet_rate` | 4,7% |
| 4° | `f16_tcpudp_len` | 4,3% |
| 5° | `f01_ip_time_interval` | ~0% |
| 6°–9° | demais features | ~0% |

**90,9% da capacidade discriminativa está nas 2 primeiras features.** O modelo aprendeu a assinatura do ataque pelo conteúdo: *payload SOME/IP de tamanho característico das notificações ADAS, enviado sem qualquer variação*.

### Comparativo com labeling anterior (por IP):

| Feature | Importância (IP) | Importância (conteúdo) | Interpretação |
|---|---|---|---|
| `f17_src_packet_rate` | **59,9%** | 4,7% | Modelo antigo aprendia "aquele IP manda rápido" |
| `f18_src_payload_diversity` | 23,9% | 32,2% | Sinal de repetição fortalecido |
| `f15_someip_payload_len` | 7,6% | **58,7%** | Assinatura do conteúdo ADAS emerge como principal |

Com labeling por IP, o modelo aprendia o **comportamento do IP** (taxa alta). Com labeling por conteúdo, aprendeu a **assinatura do ataque** (payload ADAS específico, sem variedade) — um discriminador muito mais robusto e alinhado com a spec.

---

## Resultados

### Métricas no conjunto de teste

| Classe | Precision | Recall | F1-Score | Suporte |
|---|---|---|---|---|
| Normal | 1,0000 | 1,0000 | 1,0000 | 1.994.470 |
| DoS | 1,0000 | 0,9996 | **0,9998** | 34.696 |
| **Média macro** | 1,0000 | 0,9998 | **0,9999** | — |

**AUC-ROC: 0,99999999**

### Matriz de confusão

```
                 Previsto: Normal   Previsto: DoS
Real: Normal       1.994.470               0     ← zero falsos alarmes
Real: DoS                 13          34.683     ← 13 ataques não detectados
```

De **34.696 pacotes de ataque**, o modelo deixou passar apenas **13** (0,04%).
**Zero falsos alarmes** — nenhum pacote normal foi acusado erroneamente.

---

## Interpretação prática

O classificador DoS detecta o ataque pela assinatura SOME/IP do payload ADAS, não pelo comportamento do IP. Isso é mais robusto: se um novo atacante usar um IP diferente mas enviar as mesmas notificações `svc=0x1001`, o modelo ainda detecta.

### Limitações

| Limitação | Explicação |
|---|---|
| **Uma única simulação** | Parâmetros fixos (3.000 msgs, mesmo service_id). Um flood em outro serviço ou com payload variado pode não ser detectado. |
| **DoS lento não testado** | Um flood de baixa taxa que imita tráfego normal — `f15` e `f18` não se distanciariam o suficiente. |
| **Split aleatório** | Teste na mesma simulação que o treino — não é um cenário completamente inédito. |
| **Desequilíbrio 57:1** | Sem `scale_pos_weight`, o modelo é treinado com classe majoritária dominante — funciona bem aqui, mas pode ser frágil em outros cenários. |

---

## Resumo em uma frase

> O modelo detecta DoS por inundação com F1=0,9998 e zero falsos alarmes, identificando que as notificações ADAS do atacante têm tamanho de payload característico e são enviadas sem qualquer variação de conteúdo — assinatura diretamente derivada da spec do Kim, mais robusta que a abordagem anterior baseada em IP de origem.
