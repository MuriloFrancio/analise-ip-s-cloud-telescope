-- Estrutura do banco de metricas
-- exemplo do que vai ser criado automaticamente

-- Metadados da execução e opções de processamento.
CREATE TABLE IF NOT EXISTS meta (chave TEXT PRIMARY KEY, valor TEXT NOT NULL);
-- Progresso, erros e contadores de cada PCAP.
CREATE TABLE IF NOT EXISTS arquivos (
  arquivo TEXT PRIMARY KEY, status TEXT NOT NULL, regiao TEXT, zona TEXT,
  data_nome TEXT, hora_nome TEXT, pacotes INTEGER NOT NULL DEFAULT 0,
  tcp INTEGER DEFAULT 0, udp INTEGER DEFAULT 0, icmp INTEGER DEFAULT 0,
  ipv4 INTEGER DEFAULT 0, ipv6 INTEGER DEFAULT 0, syn INTEGER DEFAULT 0,
  synack INTEGER DEFAULT 0, rst INTEGER DEFAULT 0, rstack INTEGER DEFAULT 0,
  echo_reply INTEGER DEFAULT 0, icmp_erro INTEGER DEFAULT 0,
  primeiro_ts REAL, ultimo_ts REAL, duracao_s REAL, erro TEXT
);
-- Contagens por hora UTC e região AWS.
CREATE TABLE IF NOT EXISTS por_hora (
  hora_epoch INTEGER NOT NULL, regiao TEXT NOT NULL,
  total INTEGER DEFAULT 0, tcp INTEGER DEFAULT 0, udp INTEGER DEFAULT 0,
  icmp INTEGER DEFAULT 0, ipv4 INTEGER DEFAULT 0, ipv6 INTEGER DEFAULT 0,
  syn INTEGER DEFAULT 0, synack INTEGER DEFAULT 0, rst INTEGER DEFAULT 0,
  rstack INTEGER DEFAULT 0, echo_reply INTEGER DEFAULT 0,
  icmp_erro INTEGER DEFAULT 0,
  PRIMARY KEY(hora_epoch, regiao)
);
-- Contagens diárias por protocolo e porta de destino.
CREATE TABLE IF NOT EXISTS portas_destino (
  dia TEXT NOT NULL, protocolo TEXT NOT NULL, porta INTEGER NOT NULL,
  pacotes INTEGER DEFAULT 0, syn INTEGER DEFAULT 0,
  PRIMARY KEY(dia, protocolo, porta)
);
-- Respostas TCP agregadas por dia e porta de origem.
CREATE TABLE IF NOT EXISTS portas_origem_respostas (
  dia TEXT NOT NULL, porta INTEGER NOT NULL,
  synack INTEGER DEFAULT 0, rst INTEGER DEFAULT 0,
  PRIMARY KEY(dia, porta)
);
-- Frequência de valores de flags TCP.
CREATE TABLE IF NOT EXISTS flags_tcp (
  flags INTEGER PRIMARY KEY, pacotes INTEGER NOT NULL DEFAULT 0
);
-- Contagens de tipos e códigos ICMP.
CREATE TABLE IF NOT EXISTS icmp_tipos (
  versao INTEGER, tipo INTEGER, codigo INTEGER, pacotes INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(versao, tipo, codigo)
);
-- Pequena amostra de respostas de pacotes.
CREATE TABLE IF NOT EXISTS exemplos (
  arquivo TEXT, timestamp_utc TEXT, regiao TEXT, protocolo TEXT,
  ip_origem TEXT, porta_origem INTEGER, porta_destino INTEGER, flags TEXT,
  icmp_tipo INTEGER, icmp_codigo INTEGER
);
-- Métricas acumuladas de IPs de origem.
CREATE TABLE IF NOT EXISTS origens (
  ip_origem TEXT PRIMARY KEY, pacotes INTEGER DEFAULT 0, syn INTEGER DEFAULT 0,
  synack INTEGER DEFAULT 0, rst INTEGER DEFAULT 0, mascara_regioes INTEGER DEFAULT 0,
  arquivos_distintos INTEGER DEFAULT 0,
  max_portas_destino_distintas_em_arquivo INTEGER DEFAULT 0,
  soma_portas_destino_distintas_por_arquivo INTEGER DEFAULT 0,
  primeira_observacao REAL, ultima_observacao REAL
);
