
"""Ponto de entrada: extrai métricas de PCAPs para SQLite e CSVs."""

import argparse
import os
from pathlib import Path

from processamento import executar


# Lê os parâmetros do terminal e entrega a execução ao módulo de processamento.
def main():
    parser = argparse.ArgumentParser(
        description="Extrai métricas do Cloud Telescope diretamente de PCAPs compactados"
    )
    parser.add_argument("--zip", type=Path, help="ZIP de entrada (dispensável com --somente-exportar)")
    parser.add_argument("--saida", type=Path, default=Path("outputs/auditoria"))
    parser.add_argument("--senha", default=os.environ.get("CLOUD_TELESCOPE_ZIP_PASSWORD", ""))
    parser.add_argument("--max-arquivos", type=int, default=0, help="Limite de novos PCAPs; 0 = todos")
    parser.add_argument("--relatorio-a-cada", type=int, default=25)
    parser.add_argument("--perfil-origens", action="store_true", help="Agrega estatísticas por IP de origem")
    parser.add_argument("--somente-exportar", action="store_true", help="Gera CSV/JSON sem reler os PCAPs")
    parser.add_argument("--repetir-erros", action="store_true", help="Tenta novamente os PCAPs com erro")
    executar(parser.parse_args(), parser)


if __name__ == "__main__":
    main()
