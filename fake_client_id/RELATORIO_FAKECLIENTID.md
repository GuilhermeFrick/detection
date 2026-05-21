# Relatório: Classificador FakeClientID — SOME/IP

> **Fonte dos dados**: Alkhatib et al. 2021 — PCAPs com labels pré-definidos em CSV (label=5 para ataque).
> **Diferença em relação aos outros**: este classificador usa dados do dataset Alkhatib, não Kim 2026.

---

## O que é esse ataque?

O ataque **FakeClientID** explora o campo `client_id` do cabeçalho SOME/IP. Em condições normais, cada ECU usa um `client_id` fixo e único por sessão — é o identificador que permite ao servidor saber de qual cliente veio cada requisição e para onde enviar as respostas.

O atacante rotaciona continuamente múltiplos `client_ids` falsos nas mensagens REQUEST que envia. Isso pode:

- **Confundir o servidor** quanto à origem das requisições, impedindo o roteamento correto das respostas
- **Saturar tabelas de sessão** no servidor, causando uso excessivo de memória ou CPU
- **Mascarar a identidade** do atacante — como não há um único `client_id` associado ao IP atacante, o rastreamento por sessão se torna ineficaz

O ataque é sutil: o volume de pacotes pode ser normal, e os campos de serviço (`service_id`, `method_id`) são legítimos. A anomalia está exclusivamente na diversidade anormal de `client_ids` emitidos por um mesmo IP.

---

## Fonte dos dados

Diferente dos classificadores Kim (DoS, Fuzzy, MITM), os dados do FakeClientID vêm do dataset **Alkhatib et al. 2021**, que fornece:
- **PCAPs** com o tráfego capturado
- **Arquivos CSV** com o label de cada pacote já definido pelos autores (label=0 benigno, label=1 ataque)

O label de cada pacote foi atribuído durante a geração da simulação — nenhuma interpretação adicional da spec foi necessária.

| PCAP | CSV de labels | Conteúdo |
|---|---|---|
| `fakeClientID.pcap` | `fakeclientid1.csv` | Captura 1 — tráfego benigno + ataque |
| `fakeClientID2.pcap` | `fakeclientid2.csv` | Captura 2 — tráfego benigno + ataque |

Os labels do Alkhatib usam `label=1` para ataque. Este pipeline remapeia para `label=5` (FakeClientID) para integrar ao classificador multiclasse sem colidir com as classes Kim (DoS=1, Fuzzy=2, MITM Multi=3, MITM Single=4).

---

## Os dados

### Tamanho e balanço

| Conjunto | Total | Benigno | FakeClientID | Proporção |
|---|---|---|---|---|
| Completo | 3.920 | 2.994 (76,4%) | 926 (23,6%) | **3,2:1** |
| Treino (70%) | 2.744 | 2.096 (76,4%) | 648 (23,6%) | 3,2:1 |
| Teste (30%) | 1.176 | 898 (76,4%) | 278 (23,6%) | 3,2:1 |

O FakeClientID é o **mais balanceado** de todos os classificadores deste trabalho (3,2:1), em contraste com o DoS (57:1) e o Fuzzy (~38:1). O split usado foi 70/30 estratificado (em vez do 50/50 dos outros) por conta do volume total menor.

> **Observação**: o dataset Alkhatib é significativamente menor do que o Kim (~4M vs ~3.920 amostras). Os PCAPs são mais curtos e focados no cenário de ataque específico.

---

## As features

O classificador usa **13 features** — as 12 do pipeline MITM mais a feature exclusiva `f22`:

| Feature | O que mede | Relevância FakeClientID |
|---|---|---|
| `f01_ip_time_interval` | Intervalo temporal entre pacotes do fluxo | Complementar |
| `f08_someip_payload_change` | Distância de Hamming entre payloads consecutivos | Complementar |
| `f11_ip_length_change` | Variação de tamanho do pacote IP | Complementar |
| `f12_tcpudp_length_change` | Variação de tamanho TCP/UDP | Negligível |
| `f13_payload_repeat_rate` | Fração dos últimos 5 payloads idênticos | Negligível |
| `f15_someip_payload_len` | Tamanho do payload SOME/IP | Complementar |
| `f16_tcpudp_len` | Comprimento total TCP/UDP | Negligível |
| `f17_src_packet_rate` | Taxa de pacotes por IP (janela 1000) | Secundária (2,3%) |
| `f18_src_payload_diversity` | Diversidade de payloads do IP (janela 1000) | Complementar |
| `f19_is_sd` | Flag SOME/IP-SD (svc=0xFFFF) | Negligível |
| `f20_src_service_diversity` | Serviços únicos do IP (janela 100) | **Dominante (67,5%)** |
| `f21_is_relay_service` | Flag relay service (svc=0x100B) | Negligível |
| **`f22_src_clientid_diversity`** | **Client_ids únicos do IP em REQUESTs (janela 100)** | **Crítica (29,1%)** |

### Feature nova — `f22_src_clientid_diversity`

Esta feature foi criada especificamente para o ataque FakeClientID:

```python
win_c = state['src_clientids'][src]   # deque(maxlen=100)
if client_id is not None and msg_type < 0x80:  # apenas REQUESTs
    win_c.append(client_id)
f22 = float(len(set(win_c))) if win_c else 1.0
```

- **Atacante**: rotaciona dezenas de `client_ids` → `f22` cresce continuamente
- **ECU legítima**: usa 1–2 `client_ids` fixos → `f22` ≈ 1,0

---

## Importância das features

| Posição | Feature | Importância |
|---|---|---|
| 1° | `f20_src_service_diversity` | **67,5%** |
| 2° | `f22_src_clientid_diversity` | **29,1%** |
| 3° | `f17_src_packet_rate` | 2,3% |
| 4°–13° | demais | < 1% total |

**96,6% da capacidade discriminativa em 2 features.** A combinação de `f20` e `f22` captura exatamente o comportamento anômalo: o atacante usa múltiplos serviços e múltiplos client_ids — enquanto ECUs legítimas são especializadas (poucos serviços, client_id fixo).

### Por que `f20` (service diversity) é a mais importante?

`f20` conta os service_ids únicos emitidos pelo IP na janela de 100 pacotes. O atacante, ao rotacionar client_ids em requisições de múltiplos serviços para mascarar seu comportamento, acaba usando mais service_ids do que uma ECU legítima — que normalmente se especializa em um ou dois serviços. Esse comportamento de "varredura de serviços" inadvertida é capturado por `f20` com maior poder discriminativo do que `f22`.

---

## Resultados

| Classe | Precision | Recall | F1-Score | Suporte |
|---|---|---|---|---|
| Normal | 0,9989 | 1,0000 | 0,9994 | 898 |
| FakeClientID | 1,0000 | 0,9964 | **0,9982** | 278 |
| **Média macro** | 0,9994 | 0,9982 | **0,9988** | — |

**AUC-ROC: 0,9998**

```
                        Previsto: Normal   Previsto: FakeClientID
Real: Normal                  898                0    ← 0 falsos alarmes
Real: FakeClientID              1              277    ← 1 ataque não detectado
```

### Interpretação prática

Zero falsos positivos e apenas 1 falso negativo em 1.176 amostras de teste. O único FN corresponde provavelmente a um pacote inicial do ataque antes que a janela deslizante de `f22` acumulasse client_ids suficientes para distingui-lo do tráfego legítimo — o mesmo fenômeno de "warm-up" observado nos outros classificadores.

---

## Modelo de ameaça

| Atributo | FakeClientID |
|---|---|
| Dataset | Alkhatib et al. 2021 |
| Atacante | Nó interno à rede (acesso físico/lógico) |
| Técnica | Rotação de `client_id` em mensagens REQUEST |
| Volume | Normal — não gera flood de pacotes |
| Furtividade | **Alta** — campos service/method são legítimos, anomalia só no client_id |
| Impacto | Confusão de sessão, potencial negação de serviço por esgotamento de tabelas |

---

## Resumo comparativo — todos os classificadores

| Classificador | Dataset | F1 | FP | FN | Feature dominante | Mecanismo |
|---|---|---|---|---|---|---|
| DoS | Kim 2026 | 0,9998 | 0 | 13 | `f15` (58,7%) | Payload fixo + flood |
| Fuzzy | Kim 2026 | 0,9979 | 330 | 74 | `f08` (51,3%) | Hamming alto (payload aleatório) |
| MITM Multi | Kim 2026 | 0,9984 | 167 | 349 | `f21` (69,7%) | Service relay exclusivo |
| MITM Single | Kim 2026 | 0,9994 | 61 | 143 | `f19` (92,9%) | SD Stop Offer anômalo |
| **FakeClientID** | **Alkhatib 2021** | **0,9982** | **0** | **1** | `f20` (67,5%) | **Diversidade de serviços + client_ids** |

> O FakeClientID tem o menor dataset absoluto (~3.920 vs ~4M amostras) mas atinge F1 competitivo, demonstrando que as features comportamentais generalizam mesmo com poucos dados — o padrão de rotação de client_ids é suficientemente distinto para separação quase perfeita.

### Limitações

| Limitação | Descrição |
|---|---|
| Warm-up de janela | Os primeiros ~100 pacotes do ataque podem não ser detectados enquanto `f22` acumula client_ids |
| ECU com múltiplos serviços | Uma ECU legítima que use muitos serviços pode elevar `f20`, aumentando FP |
| Dataset pequeno | 3.920 amostras — generalização para capturas maiores não foi testada |
| Cross-dataset | Modelo treinado no Alkhatib, não testado no Kim (cenários diferentes) |
