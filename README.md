# Análise de IPs — Cloud Telescope Dataset 3

Este repositório reúne scripts Python para analisar o tráfego do **Cloud Telescope Dataset 3**, caracterizar os IPs de origem e agrupar comportamentos semelhantes com **K-Means**. 
Os resultados gerados incluem estatísticas em CSV, um bancos em SQLite e gráficos dos grupos e individuais.

Bônus script para visualizar o comportamento de todos os ip's em um período e porta selecionado no comando, voltado ao entendimento do comportamento dos ips com a divulgação de um CVE  

## O fluxo principal é: 

**PCAPs** → 

Arquivos dentro do dataset3 zipado

**extração de métricas** →

exemplo: 
|Métrica	|O que representa|
| --- | --- |
|IP de origem|	Endereço IP que enviou o pacote|
|TCP, UDP e ICMP|	Protocolos identificados no tráfego|
|Portas de destino|	Portas para as quais os pacotes foram enviados|
|SYN, SYN-ACK e RST|	Flags TCP associadas a tentativas de conexão, respostas e redefinições|
|Data e horário|	Momento em que o pacote foi capturado|
|Região AWS|	Região do sensor que recebeu o pacote|
|Total de pacotes|	Quantidade de pacotes contabilizados|

**análise da distribuição** → 
|Faixa	Pacotes por IP|
| --- |
|Baixa	1–9|
|Média	10–999|
|Alta	1.000 ou mais|

**seleção de IPs** → 

Escolher a quantidade de ip's que quer em cada faixa tendo esse total em vista
|Faixa	Pacotes por IP	|IPs disponíveis|
| --- | --- |
|Baixa	1–9|	1.456.097|
|Média	10–999|	386.082|
|Alta	1.000 ou mais|	22.932|

**reconstrução dos históricos** →

Voltamos ao Dataset3 para verificar o historico desses ip que foram escolhidos, pensando em visualizar as seguintes informações:
  - Atividade diária: em quais dias cada IP apareceu e quantos pacotes enviou.
  - Protocolos: quantos pacotes TCP, UDP e ICMP apresentou.
  - Flags TCP: quantidade de SYN, SYN-ACK e RST.
  - Portas de destino: quais portas foram utilizadas e quantas portas distintas foram observadas.
  - Regiões AWS: em quantos sensores ou regiões o IP foi observado.

**clusterização** → 

1 - Calculamos as características de cada IP

|Característica|	O que queremos entender|
| --- | --- |
|Média de pacotes por dia ativo|	Intensidade da atividade|
|Proporção de dias observados|	Frequência ao longo do período|
|Maior intervalo sem observação|	Continuidade ou interrupção da atividade|
|Concentração no dia mais ativo|	Se o tráfego ocorreu em um pico|
|Quantidade de portas distintas|	Diversidade das portas utilizadas|
|Proporção de regiões AWS|	Abrangência entre sensores|
|Proporção UDP|	Participação do tráfego UDP|
|Proporção ICMP|	Participação do tráfego ICMP|
|Proporção RST/TCP|	Frequência de redefinições TCP|
|Proporção SYN-ACK/TCP|	Frequência de respostas SYN-ACK|

2 - As características possuem escalas muito diferentes então
para que uma característica não domine a clusterização apenas 
por possuir números maiores, utilizamos o 'StandardScaler' como
transformações logarítmicas em determinadas características 
e limitamos valores extremos para reduzir sua influência

3 - O K-Means começa com sete centros de grupos ('centroides') e trabalha iterativamente:
  1. Associa cada IP ao centro mais próximo, considerando suas dez características padronizadas.
  2. Recalcula o centro de cada grupo conforme os IPs associados.
  3. Repete o processo até a convergência do algoritmo.
Assim, os IPs que apresentam características semelhantes tendem a ficar no mesmo grupo.

4. Avaliamos os grupos encontrados
O código também compara configurações de 3 a 9 grupos, utilizando duas métricas:
*Silhouette*: avalia a separação e a coesão dos clusters. No experimento com
7 grupos, obtivemos aproximadamente 0,387.
*ARI de estabilidade*: compara agrupamentos obtidos com sementes diferentes.
Encontramos aproximadamente 0,998

6. Interpretamos os sete perfis

Esses foram os resultados da amostra com 60mil ips sendo 12.068 de baixa, 25.000 media, 22.932 alta

| Grupo | IPs | Comportamento predominante |
|:---:|---:|---|
| G1 | 8.025 | Atividade persistente e diversificada |
| G2 | 4.372 | TCP com redefinições frequentes |
| G3 | 5.934 | Tráfego predominantemente ICMP |
| G4 | 16.068 | Atividade recorrente moderada |
| G5 | 5.248 | Tráfego predominantemente UDP |
| G6 | 470 | Respostas SYN-ACK predominantes |
| G7 | 19.883 | Atividade curta ou pouco frequente |
| **Total** | **60.000** | **7 perfis comportamentais** |


**gráficos**. 

O que podemos visualizar com os gráficos
  - Atividade diária: quantos pacotes um IP enviou em cada dia.
  - Atividade mensal: como o volume de tráfego mudou ao longo dos meses.
  - Comparação entre grupos: diferenças na atividade dos clusters G1 a G7.
  - IPs individuais: comportamento de IPs selecionados dentro de cada grupo.
  - Picos de atividade: períodos em que determinados IPs apresentaram aumentos de tráfego.

Há também uma investigação opcional que compara o tráfego de uma porta TCP antes e depois de uma data de referência, no caso uma divulgação de CVE.

## 1. Requisitos e instalação

Você precisará do código deste repositório, do **ZIP original do Dataset 3** e da senha correspondente

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Informar o dataset

Configure o caminho para o ZIP **na sessão atual do PowerShell** (melhor uso e no terminal do Vs):

```powershell
$dataset = "Caminho\cloud_telescope_raw_dataset_3.zip"
```
se quiser usar a senha como variável para diminuir o comando

```powershell
$env:CLOUD_TELESCOPE_ZIP_PASSWORD = "senha"
```

> No PowerShell, o acento grave `` ` `` no fim da linha permite continuar o comando na linha seguinte. Não deixe espaços depois dele.

## 2. Scripts utilizados

| Script | Finalidade |
| --- | --- |
| `extrair_metricas_pcaps.py` | Lê os PCAPs, contabiliza métricas do tráfego e cria o SQLite da auditoria. |
| `analisar_distribuicao_ips.py` | Examina quantos IPs existem e como se distribuem por volume de pacotes. |
| `main_perfis_ips.py` | Seleciona a amostra, reconstrói históricos e exporta CSVs por IP. |
| `clusterizar.py` | Aplica K-Means e gera os grupos G1–G7 e gráficos de comparação. |
| `gerar_graficos_temporais_cloud.py` | Gera séries temporais dos grupos e gráficos de IPs individuais. |
| `investigar_cve.py` | Opcional: compara o tráfego em uma porta TCP com uma data de referência. |

Os demais arquivos em `scripts/` são **módulos auxiliares** importados automaticamente: `capturas.py` interpreta pacotes, `metricas.py` contabiliza indicadores, `banco.py` gerencia a auditoria SQLite, `processamento.py` coordena a leitura, `exportacao.py` produz os CSVs gerais e os módulos `perfis_*` implementam seleção, banco e históricos. O arquivo `sql/schema.sql` define as tabelas da auditoria e **não precisa ser executado manualmente**.

## 3. Primeiro teste: processar poucos PCAPs

Antes de executar o dataset inteiro, teste a leitura do ZIP e a instalação das bibliotecas com até 30 capturas:

```powershell
python .\scripts\extrair_metricas_pcaps.py `
  --zip "$dataset" `
  --saida ".\outputs\teste\auditoria" `
  --perfil-origens `
  --max-arquivos 30
```

O script cria `auditoria.sqlite`, `resumo_geral.json` e CSVs com as contagens. Verifique se os arquivos são gerados e se o terminal não registra erros de senha ou leitura.

Para evitar misturar resultados, os comandos seguintes usam `outputs/completo`, separado de `outputs/teste`.

## 4. Extração **completa** das métricas

```powershell
python .\scripts\extrair_metricas_pcaps.py `
  --zip "$dataset" `
  --saida ".\outputs\completo\auditoria" `
  --perfil-origens `
  --relatorio-a-cada 100
```

| Parâmetro | Uso |
| --- | --- |
| `--zip` | Caminho do ZIP original. |
| `--saida` | Diretório de saída do banco e dos arquivos exportados. |
| `--perfil-origens` | Ativa a contagem individual por IP de origem; **necessário para a amostragem posterior**. |
| `--max-arquivos 30` | Limita a quantidade de novos PCAPs; omitido, processa todos os pendentes. |
| `--relatorio-a-cada 100` | Define a frequência das mensagens de progresso. |
| `--senha` | Senha do ZIP, alternativa à variável de ambiente. |
| `--repetir-erros` | Reprocessa capturas anteriormente registradas com erro. |
| `--somente-exportar` | Recria os CSVs e o JSON a partir do SQLite, sem reler os PCAPs. |

**Saídas principais:** `auditoria.sqlite`, `resumo_geral.json`, `resumo_por_arquivo.csv`, `contagens_dia_regiao.csv`, `contagens_hora_regiao.csv`, `portas_destino_dia.csv`, `flags_tcp.csv` e `tipos_icmp.csv`.

Confira no `resumo_geral.json` os campos `arquivos_processados` e `arquivos_com_erro`. Mantenha o mesmo ZIP e a opção `--perfil-origens` ao retomar a mesma auditoria; utilize outra pasta de saída para um experimento diferente.

## 5. Distribuição dos IPs

Esta etapa consulta o SQLite da auditoria; **não reabre o ZIP**. Mostra total de IPs distintos, percentis de pacotes por IP, faixas de atividade e origens com maior volume.

```powershell
python .\scripts\analisar_distribuicao_ips.py `
  --banco ".\outputs\completo\auditoria\auditoria.sqlite" `
  --saida ".\outputs\completo\distribuicao"
```

| Parâmetro | Uso |
| --- | --- |
| `--banco` | SQLite gerado na etapa anterior. |
| `--saida` | Destino dos relatórios de distribuição. |

**Saídas:** `distribuicao_ips.json`, `faixas_volume_observadas.csv` e `top_20_origens.csv`.

### Alterar faixas e percentis

No início de `scripts/analisar_distribuicao_ips.py`, é possível ajustar as constantes usadas.

```python
PERCENTIS = [25, 50, 75, 90, 95, 99, 99.9]
FAIXAS = [
    ("Baixa", 1, 9),
    ("Média", 10, 999),
    ("Alta", 1000, None),
]
```

Esses limites não alteram automaticamente o seletor: a lógica das faixas da amostra está em `scripts/perfis_banco.py`, na função `faixa()`.

## 6. Selecionar a amostra de IPs

A auditoria pode identificar milhões de origens. Nesta etapa, o script escolhe uma amostra de IPs com base em **três faixas de volume**: baixa (1–9 pacotes), média (10–999) e alta (1.000 ou mais). A seleção é reproduzível com uma semente.

Exemplo usado no estudo com **60.000 IPs**:

```powershell
python .\scripts\main_perfis_ips.py `
  --fase selecionar `
  --banco ".\outputs\completo\auditoria\auditoria.sqlite" `
  --saida ".\outputs\completo\amostra_60000" `
  --baixa 12068 `
  --media 25000 `
  --alta 22932 `
  --semente 42
```

| Parâmetro | Uso |
| --- | --- |
| `--fase selecionar` | Seleciona os IPs, ainda sem reler os PCAPs. |
| `--baixa`, `--media`, `--alta` | Quantidades **máximas** selecionadas em cada faixa; ajuste ao tamanho desejado. |
| `--semente 42` | Fixa o sorteio pseudoaleatório; mudar a semente pode mudar os IPs escolhidos. |
| `--banco` | Banco da auditoria completa. |
| `--saida` | Pasta da amostra e do banco dos históricos. |

**Saídas:** `ips_selecionados.csv`, `amostra_info.json` e `perfis.sqlite`.

A seleção pode retornar menos IPs do que o solicitado se uma faixa tiver menos candidatos.

## 7. Reconstruir os históricos dos IPs

A primeira leitura armazenou contagens agregadas. Esta fase **relê os PCAPs** para reconstruir, somente para os IPs selecionados, as observações por dia, portas e protocolos. Os resultados são guardados no `perfis.sqlite`; não é preciso repetir a extração geral.

```powershell
python .\scripts\main_perfis_ips.py `
  --fase historico `
  --zip "$dataset" `
  --banco ".\outputs\completo\auditoria\auditoria.sqlite" `
  --saida ".\outputs\completo\amostra_60000" `
  --relatorio-a-cada 100
```

| Parâmetro | Uso |
| --- | --- |
| `--fase historico` | Inicia ou retoma a leitura dos históricos. |
| `--zip` | Mesmo ZIP utilizado na auditoria. |
| `--banco` | Auditoria usada como referência. |
| `--saida` | **Mesma pasta** da fase `selecionar`. |
| `--somente-auditados` | Restringe aos PCAPs com status `ok` na auditoria. |
| `--limitar-arquivos 30` | Limita a quantidade de capturas novas na fase de teste. |
| `--relatorio-a-cada` | Intervalo das mensagens de progresso. |
| `--senha` | Senha, se a variável de ambiente não estiver configurada. |

Uma execução interrompida pode ser retomada com os mesmos parâmetros e arquivos, sem perder o que já foi gravado.

### Exportar os históricos

Ao terminar a reconstrução, exporte os CSVs para a clusterização:

```powershell
python .\scripts\main_perfis_ips.py `
  --fase exportar `
  --saida ".\outputs\completo\amostra_60000"
```

**Saídas:** `resumo_ips.csv` (uma linha por IP), `historico_diario_ips.csv` (uma linha por IP/dia), `atividade_mensal_ips.csv` e `resumo_piloto.json`.

## 8. Clusterização dos perfis

O script lê os CSVs dos históricos, calcula características comportamentais, padroniza os valores e executa **K-Means**. Os grupos G1–G7 são identificadores atribuídos ao resultado e podem mudar com outra amostra ou outro número de clusters.

```powershell
python .\scripts\clusterizar.py `
  --entrada ".\outputs\completo\amostra_60000" `
  --saida ".\outputs\completo\clusters_60000" `
  --grupos 7 `
  --total-regioes 26
```

| Parâmetro | Uso |
| --- | --- |
| `--entrada` | Diretório dos CSVs exportados dos históricos. |
| `--saida` | Destino das classificações, validações e gráficos. |
| `--grupos 7` | Quantidade de clusters K-Means (na versão atual, de 3 a 9). |
| `--total-regioes 26` | Referência utilizada para normalizar uma característica de abrangência entre sensores AWS; **não filtra regiões**. |

**Saídas:** `ips_clusterizados.csv`, `resumo_clusters.csv`, `validacao_quantidade_grupos.csv`, `exemplos_representativos.csv`, `resumo_clusterizacao.json` e gráficos como `grafico_perfis_pca.png`.

O terminal apresenta Silhouette e ARI de estabilidade.

## 9. Gráficos temporais e casos individuais

Com os IPs classificados, este script gera comparações mensais de G1–G7 e gráficos de IPs individuais.

```powershell
python .\scripts\gerar_graficos_temporais_cloud.py `
  --entrada ".\outputs\completo\amostra_60000" `
  --clusters ".\outputs\completo\clusters_60000\ips_clusterizados.csv" `
  --saida ".\outputs\completo\graficos_60000" `
  --ips-por-grupo 3
```

| Parâmetro | Uso |
| --- | --- |
| `--entrada` | CSVs dos históricos. |
| `--clusters` | `ips_clusterizados.csv` gerado pelo K-Means. |
| `--saida` | Destino dos PNGs e CSVs de indicadores. |
| `--ips-por-grupo 3` | Seleciona até três IPs representativos de cada grupo. |
| `--grupos-foco G1 G4` | Exibe apenas os grupos informados. |
| `--casos IP1 IP2` | Gera gráficos dos endereços informados, se estiverem na amostra. |
| `--inicio-mes 2023-10` | Primeiro mês representado (formato `AAAA-MM`). |
| `--fim-mes 2024-03` | Último mês representado; pode incluir meses parciais. |

Exemplo: apenas G1 e G4, com cinco IPs por grupo:

```powershell
python .\scripts\gerar_graficos_temporais_cloud.py `
  --entrada ".\outputs\completo\amostra_60000" `
  --clusters ".\outputs\completo\clusters_60000\ips_clusterizados.csv" `
  --saida ".\outputs\completo\graficos_G1_G4" `
  --grupos-foco G1 G4 `
  --ips-por-grupo 5
```

**Saídas:** comparações mensais, CSVs de indicadores, gráficos de intensidade de cada grupo e gráficos de pacotes/portas/dias observados para IPs individuais.

Por padrão, o código exibe de outubro de 2023 a fevereiro de 2024.

<img width="1773" height="618" alt="image" src="https://github.com/user-attachments/assets/4a189da6-4dbc-4bfe-9d55-29f6de98b8c1" />
<img width="1493" height="783" alt="image" src="https://github.com/user-attachments/assets/f57a8499-5cb9-44dc-9030-0a5fd362b37f" />
<img width="1493" height="783" alt="image" src="https://github.com/user-attachments/assets/7a6144c2-5ffa-4dfe-a273-d661b0b2e47d" />

<img width="1493" height="783" alt="image" src="https://github.com/user-attachments/assets/aee3ed24-d665-483a-898e-bd0be96cfd22" />
<img width="1492" height="783" alt="image" src="https://github.com/user-attachments/assets/ff4389cc-b1e3-43c0-967b-7eac85a7babc" />



## 10. Bonus: análise de porta TCP e divulgação de CVE

Esse script compara o tráfego destinado a uma porta TCP em torno de uma data de referência. Diferentemente dos gráficos anteriores, a investigação **detalhada por IP e por cluster relê os PCAPs**, pois os CSVs agregados não armazenam a combinação completa.

Exemplo: porta TCP 61616, com referência em 27/10/2023:

```powershell
python .\scripts\investigar_cve.py `
  --zip "$dataset" `
  --clusters ".\outputs\completo\clusters_60000\ips_clusterizados.csv" `
  --banco ".\outputs\completo\auditoria\auditoria.sqlite" `
  --saida ".\outputs\completo\cve_46604" `
  --evento 2023-10-27 `
  --porta 61616 `
  --dias 180
```

| Parâmetro | Uso |
| --- | --- |
| `--evento` | Data de referência UTC, no formato `AAAA-MM-DD`. |
| `--porta` | Porta TCP de destino investigada. |
| `--dias` | Número de dias **antes e depois** do evento. |
| `--clusters` | CSV de classificação dos IPs. |
| `--zip`, `--banco`, `--somente-auditados` | Fontes de dados e restrição às capturas auditadas. |
| `--saida` | Diretório dos dados da investigação; use outro ao trocar porta ou evento. |
| `--max-arquivos` | Limita PCAPs novos para teste. |
| `--relatorio-a-cada` | Frequência das mensagens de progresso. |
| `--senha` | Senha do ZIP, se necessário. |
| `--somente-exportar` | Regenera CSVs e gráficos do `investigacao.sqlite` existente, sem reler PCAPs. |

**Saídas:** `investigacao.sqlite`, `serie_diaria_porta.csv`, `serie_diaria_clusters.csv`, `por_ip_dia.csv`, `comparacao_clusters.csv`, `grafico_porta_todo_dataset.png`, `grafico_porta_amostra.png` e `grafico_clusters_porta.png`.

Para uma janela maior, pode usar `--dias 180`, os gráficos limitam a visualização ao primeiro e último timestamp registrado na auditoria.

Se a investigação já estiver concluída e você alterar somente o **estilo dos gráficos**, repita os mesmos parâmetros e acrescente `--somente-exportar`:

```powershell
python .\scripts\investigar_cve.py `
  --zip "$dataset" `
  --clusters ".\outputs\completo\clusters_60000\ips_clusterizados.csv" `
  --banco ".\outputs\completo\auditoria\auditoria.sqlite" `
  --saida ".\outputs\completo\cve_46604" `
  --evento 2023-10-27 `
  --porta 61616 `
  --dias 14 `
  --somente-exportar
```

Para ajustar a aparência dos gráficos, procure as chamadas a `plt.plot()` e `plt.savefig()` dentro de `exportar()` em `investigar_cve.py`.

## 11. Conferência e resolução de problemas

| Situação | Verificação |
| --- | --- |
| `argument --zip: expected one argument` | Confira se `$dataset` está definido nesta sessão (`Test-Path $dataset`). |
| ZIP inexistente ou senha incorreta | Revise caminho, senha e instalação do `pyzipper`. |
| `Parametros numericos invalidos` | Verifique quantidades e limites; `--alta -1` não é aceito nesta versão. |
| Amostra já existe | Para selecionar outros IPs, escolha outra pasta em `--saida`. |
| CSV de cluster não encontrado | Confira se a clusterização terminou e se o caminho de `--clusters` está correto. |
| Gráfico sem dados | Confira porta, data, intervalo e presença de capturas; zero observado não é o mesmo que ausência comprovada de atividade. |
| Alterar só gráficos da CVE | Use `--somente-exportar` com a mesma investigação e seus mesmos parâmetros. |

Para consultar as opções diretamente na sua versão do código, execute:

```powershell
python .\scripts\extrair_metricas_pcaps.py --help
python .\scripts\main_perfis_ips.py --help
python .\scripts\clusterizar.py --help
python .\scripts\gerar_graficos_temporais_cloud.py --help
python .\scripts\investigar_cve.py --help
```

### Referência do estudo realizado

A execução integral deste projeto analisou **21.326 PCAPs**, totalizando **541.251.904 pacotes** e **1.865.111 IPs de origem distintos**. A amostra de **60.000 IPs** foi dividida em 12.068 de baixa atividade, 25.000 de média e 22.932 de alta. A clusterização com `--grupos 7` identificou os perfis G1–G7.

<img width="2080" height="832" alt="image" src="https://github.com/user-attachments/assets/7369ebf7-64bc-4f1f-973f-3c2b2587832f" />

<img width="1500" height="675" alt="image" src="https://github.com/user-attachments/assets/48ca29d5-30bb-4c9e-bd91-956f977c131c" />

<img width="1500" height="750" alt="image" src="https://github.com/user-attachments/assets/80f67875-44e4-4166-ba0f-a4060b3b2bfe" />


---

**Melhorias podem ocorrer, principalmente na criação de graficos, diversidade dos grupos e no modo como eles são clusterizados na escolha de ip's entre outros ajustes pequenos.**

---
