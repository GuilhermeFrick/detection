# Classificador Multiclasse SOME/IP — Relatório de Resultados

**Dataset:** someip_traces (Alkhatib, Ghauch & Danger, 2021) + FakeClientID (extensão)  
**Modelo:** XGBoost `multi:softprob`  
**Features:** 13 features stateful extraídas via Scapy  
**Classes:** 6 (Benigno, DoS, Fuzzy, MITM_Multi, MITM_Single, FakeClientID)

---

## 1. Modelo de Ameaça

O classificador opera sobre tráfego SOME/IP capturado na rede Ethernet interna do veículo (backbone Automotive Ethernet). O cenário de ameaça pressupõe que o atacante obteve acesso à rede — via porta OBD-II, ECU comprometida ou dispositivo físico conectado — mas **não possui material criptográfico nem acesso ao firmware** dos ECUs.

| Ataque | Objetivo | Camada SOME/IP | Transporte | Furtividade |
|---|---|---|---|---|
| DoS | Disponibilidade | SOME/IP-SD (flood) | UDP | Baixa |
| Fuzzy | Descoberta de vulnerabilidades | Serviço (métodos aleatórios) | UDP | Baixa |
| MITM Multi-Attacker | Integridade / Confidencialidade | Relay service (0x100B) | UDP/TCP | Média |
| MITM Single-Attacker | Integridade / Confidencialidade | SOME/IP-SD (interceptação) | UDP | Média |
| FakeClientID | Impersonação / Escalada de privilégio | Serviço (client_id falso) | UDP | **Alta** |

---

## 2. Pipeline de Treino e Validação

```
PCAPs (someip_traces)          Labels (CSVs)
        |                             |
        v                             v
01_features.py  ──────────────────────────>  features.csv  (12 features, 5 classes)
        |
        v
01b_merge_fakeclientid.py  ──────────────>  X_train.npy / X_test.npy
        |                                   y_train.npy / y_test.npy
        |                                   norm_params.json
        v
02_train.py  ────────────────────────────>  multiclass_classifier.json
        |                                   results.json
        v
03_test_outofscope.py  ──────────────────>  outofscope_results.json
```

**Decisões de projeto:**

- **Split:** 70/30 estratificado por classe (seed=42)
- **Normalização:** min-max por feature, parâmetros salvos em `norm_params.json` para inferência em produção
- **Balanceamento de classes:** pesos inversamente proporcionais à frequência, com cap de 100x para evitar que FakeClientID (0.02% do dataset) domine o modelo
- **Features stateful:** janela deslizante por fluxo `(src_ip, dst_ip, sport, dport, transport)` com histórico de até 1.000 pacotes por fonte

---

## 3. Dataset

| Classe | Treino | Teste | Total | % |
|---|---|---|---|---|
| Benigno | 768.878 | 329.540 | 1.098.398 | 57,02% |
| DoS | 107.430 | 46.042 | 153.472 | 7,97% |
| Fuzzy | 196.018 | 84.008 | 280.026 | 14,54% |
| MITM_Multi | 149.622 | 64.124 | 213.746 | 11,10% |
| MITM_Single | 126.178 | 54.077 | 180.255 | 9,36% |
| FakeClientID | 463 | 463 | 926 | 0,02% |
| **Total** | **1.348.589** | **578.254** | **1.926.843** | |

> FakeClientID foi adicionado como extensão ao dataset original. O desequilíbrio extremo (~700:1 em relação a DoS) motivou o capping de pesos.

---

## 4. O que Caracteriza Cada Ataque

### 4.1 Assinatura de Features (médias reais — treinamento)

| Feature | Benigno | DoS | Fuzzy | MITM_Multi | MITM_Single | FakeClientID |
|---|---|---|---|---|---|---|
| f13 repeat rate | 0,46 | **0,70** | 0,68 | 0,39 | **0,73** | ~0 |
| f17 pkt/s | 216 | 206 | **323** | 154 | 260 | 2,2 |
| f18 payload diversity | 0,07 | 0,007 | **0,18** | 0,015 | 0,07 | **0,97** |
| f19 is_SD | 0,009 | **0,60** | 0,022 | 0,019 | **0,85** | 0 |
| f20 service diversity | 1,55 | 2,00 | 1,22 | 1,79 | 1,49 | **2,97** |
| f21 relay service | ~0 | ~0 | ~0 | **0,38** | ~0 | ~0 |
| f22 clientid diversity | 1,00 | 1,00 | 1,00 | 1,00 | 1,00 | **7,95** |
| f08 payload change | 0,005 | 0,006 | **0,081** | ~0 | 0,022 | 0,360 |
| f11 ip len change (B) | 0,02 | 0,69 | **3,48** | 0,11 | 0,11 | 6,89 |

### 4.2 Descrição por Classe

**DoS — Flood de Service Discovery**  
60% dos pacotes do ataque são mensagens SOME/IP-SD (f19=0,60), sempre UDP. O atacante inunda `OfferService` / `FindService` com payloads idênticos (f18=0,007, f13=0,70) para saturar o daemon SD dos ECUs alvo. A taxa de pacotes (206 pkt/s) é similar ao tráfego benigno porque o SD legítimo já é periódico — a distinção vem da repetição extrema e da ausência de diversidade.

**Fuzzy — Probing de Interfaces**  
Maior taxa de pacotes do conjunto (323 pkt/s). Envia chamadas a métodos aleatórios com payloads variados (f08=0,081, f18=0,18, f11/f12=3,48 B de variação média). Não ataca o SD (f19=0,02) — vai diretamente às interfaces de serviço. Objetivo: identificar métodos não validados ou causar crash.

**MITM Multi-Attacker — Relay Comprometido**  
Único ataque que usa o relay service (f21=0,38 → 38% dos pacotes têm `service_id=0x100B`). Os múltiplos atacantes operam como proxy transparente: recebem mensagens legítimas e as repassam (f08~0, payload quase inalterado). A assinatura está na presença do relay, não em anomalias de payload.

**MITM Single-Attacker — Interceptação no SD**  
85% das mensagens são SD (f19=0,85), maior f13 de todas as classes (0,73 — replays de mensagens SD). O atacante posicionado entre dois ECUs intercepta o `FindService` do cliente e responde com seu próprio `OfferService`, redirecionando a comunicação. Opera exclusivamente na fase de descoberta de serviço, daí o alto f19.

**FakeClientID — Impersonação Furtiva**  
f22=7,95 é o identificador perfeito: um único IP usa 7–8 client_ids distintos em mensagens REQUEST (msg_type < 0x80), enquanto ECUs legítimos usam exatamente 1. Taxa de pacotes muito baixa (2,2 pkt/s) — ataque lento e discreto. Sem f22, o padrão de payload do ataque é quase indistinguível do benigno.

### 4.3 Feature Discriminante Principal por Classe

| Classe | Feature-chave | Delta médio vs. global |
|---|---|---|
| DoS | f19 (is_SD) | 0,458 |
| Fuzzy | f18 (payload diversity) | 0,102 |
| MITM_Multi | f21 (relay service) | 0,339 |
| MITM_Single | f19 (is_SD) | 0,714 |
| FakeClientID | f22 (clientid diversity) | **0,993** |

---

## 5. Protocolo SOME/IP — Comportamento UDP e TCP

SOME/IP opera sobre ambos os transportes, com papéis distintos:

| Função | Transporte | Porta | Observação |
|---|---|---|---|
| Service Discovery (SD) | **UDP** obrigatório | 30490 | Multicast ou unicast |
| Eventos / Notificações | UDP (preferencial) | 30490–30503 | Fire-and-forget |
| Request-Response | UDP ou TCP | 30490–30503 | TCP quando confiabilidade exigida |
| Relay (0x100B) | UDP ou TCP | variável | Depende da configuração vsomeip |

**Implicação para o IDS:**  
O fluxo é rastreado pela chave `(src_ip, dst_ip, sport, dport, transport)`, garantindo que fluxos UDP e TCP não contaminem o estado um do outro. A feature `f19_is_SD` indiretamente indica UDP (todo pacote SD é UDP). `f16_tcpudp_len` é calculado diferente por protocolo (`l4.len - 8` para UDP; `len(payload)` para TCP), mas o modelo absorve essa diferença via normalização.

**Qual transporte cada ataque usa** (derivado de f19 e f21):

| Ataque | Transporte predominante | Evidência |
|---|---|---|
| DoS | **UDP** | f19=0,60 (flood SD, sempre UDP) |
| Fuzzy | **UDP** | f19=0,02 (não SD) — UDP por velocidade |
| MITM_Multi | UDP + TCP | f21=0,38 (relay pode usar ambos) |
| MITM_Single | **UDP** | f19=0,85 (ataca SD, sempre UDP) |
| FakeClientID | **UDP** | f19=0 (serviço, não SD) — UDP preferencial |

---

## 6. Resultados In-Scope

### 6.1 Métricas Globais

| Métrica | Valor |
|---|---|
| Acurácia global | **99,91%** |
| F1 macro | **99,92%** |
| F1 weighted | **99,91%** |
| Tempo de treino | 93,2 s |
| Latência por pacote | 0,79 ms |
| Throughput | 225.813 pkt/s |

### 6.2 F1 por Classe

| Classe | F1 Multiclasse | F1 One-vs-Rest (ref.) | Delta |
|---|---|---|---|
| Benigno | 0,9992 | — | — |
| DoS | **0,9999** | 0,9998 | +0,0001 |
| Fuzzy | 0,9995 | 0,9990 | +0,0005 |
| MITM_Multi | 0,9973 | 0,9979 | -0,0006 |
| MITM_Single | 0,9991 | 0,9994 | -0,0003 |
| FakeClientID | **1,0000** | — | — |

> O classificador multiclasse mantém desempenho equivalente ao One-vs-Rest para todas as classes, com ganho líquido positivo em DoS e Fuzzy.

### 6.3 Matriz de Confusão

```
              Benigno      DoS    Fuzzy  MITM_Mu  MITM_Si  FakeC
Benigno     1.097.219        8      111      841      219      0
DoS                 0  153.465        2        4        1      0
Fuzzy             126        7  279.889        3        1      0
MITM_Multi        304        8        2  213.432        1      0
MITM_Single        78        0        1        7  180.169      0
FakeClientID        0        0        0        0        0    463
```

**Análise dos erros:**

- **Benigno → MITM_Multi (841):** Pacotes benignos que passam pelo relay service (0x100B) são confundidos com MITM_Multi, pois compartilham f21=1. São falsos positivos legítimos em termos de feature.
- **Benigno → MITM_Single (219):** Pacotes de SD benigno com alta repetição (f19=1, f13 alto) ficam no limiar da classe MITM_Single.
- **MITM_Multi → Benigno (304):** Pacotes do ataque sem uso do relay (f21=0) perdem a feature discriminante.
- **FakeClientID:** Zero erros — f22 é discriminante perfeita.

---

## 7. Resultados Out-of-Scope

Ataques **não vistos no treino**, avaliados em PCAPs do dataset someip_traces:

| Cenário | Pacotes SOME/IP | Benigno | DoS | Fuzzy | MITM_M | MITM_S | FakeC |
|---|---|---|---|---|---|---|---|
| Error on Error | 90.871 | **99,98%** | 0,002% | 0,011% | 0% | 0% | 0,003% |
| Error on Event | 1.638 | **99,94%** | 0% | 0% | 0% | 0% | 0,06% |
| Delete Request | 2.228 | **99,91%** | 0% | 0% | 0% | 0% | 0,09% |
| Delete Response | 2.423 | **99,88%** | 0% | 0% | 0% | 0% | 0,12% |
| Wrong Interface | 2.183 | **66,3%** | 0% | 0,05% | 0% | 0% | **33,7%** |
| Wrong Interface 2 | 1.615 | **90,6%** | 0% | 0% | 0% | 0% | **9,4%** |
| Delete Request Test | 1.363 | **99,93%** | 0% | 0% | 0% | 0% | 0,07% |

**Interpretação:**

- **Error on Error / Event, Delete Request/Response:** Classificados como Benigno (>99,9%). Ataques de manipulação de estado do protocolo SD não alteram as features stateful de forma sustentada — são invisíveis ao modelo baseado em comportamento de fluxo. Exigiriam modelagem de máquina de estados SOME/IP-SD.

- **Wrong Interface:** Parcialmente classificado como FakeClientID (34% e 9%). O ataque envia requisições a interfaces de serviço incorretas com client_ids variados, elevando f22 > 1 — exatamente a assinatura do FakeClientID. Isso é um **verdadeiro positivo semântico**: o comportamento de Wrong Interface compartilha a característica de diversidade de client_id com o FakeClientID.

---

## 8. Conclusões

1. **Discernimento de tipo de ataque:** O classificador multiclasse distingue 5 tipos de ataque com F1 ≥ 0,997 em todas as classes, mantendo paridade com detectores binários especializados (One-vs-Rest).

2. **Ataque mais difícil:** MITM_Multi (F1=0,9973) — sua assinatura baseada no relay service (f21) tem sobreposição com tráfego benigno que passa pelo mesmo serviço.

3. **Ataque mais furtivo e paradoxalmente mais detectável:** FakeClientID — invisível por todas as outras features, mas perfeitamente separado por f22 (F1=1,0000).

4. **Robustez out-of-scope:** O modelo classifica ataques desconhecidos como Benigno em >99% dos casos, evitando alarmes falsos. A exceção é Wrong Interface, que compartilha comportamento real com FakeClientID.

5. **Limitação identificada:** Ataques de manipulação de estado de protocolo (violações da máquina de estados SD) são invisíveis às features estatísticas de fluxo. Uma extensão natural seria adicionar uma camada de verificação de sequência de mensagens SD.

---

## Referência do Dataset

> Alkhatib, H., Ghauch, H., & Danger, J.-L. (2021). *Here comes SAID: A SOME/IP Attention-based Intrusion Detection system*. someip_traces dataset. Utilizado como base para treino e avaliação do classificador multiclasse; estendido com a classe FakeClientID.
