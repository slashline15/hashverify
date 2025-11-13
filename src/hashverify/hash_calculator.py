"""Módulo para cálculo de hashes de arquivos."""

import hashlib
from pathlib import Path
from typing import Iterator, Tuple, List
import os

from .config import EXTENSOES_RELEVANTES, ALGORITMOS_HASH
from .models import FileAnalysisResult, DetectionStatus


class HashCalculator:
    """Calculadora de hashes de arquivos.

    Attributes:
        algorithm: Algoritmo de hash a ser usado.
        block_size: Tamanho do bloco para leitura de arquivos.
    """

    def __init__(self, algorithm: str = 'sha256', block_size: int = 4096) -> None:
        """Inicializa o calculador de hash.

        Args:
            algorithm: Algoritmo de hash ('md5', 'sha1', 'sha256').
            block_size: Tamanho do bloco para leitura de arquivos em bytes.

        Raises:
            ValueError: Se o algoritmo não for suportado.
        """
        if algorithm not in ALGORITMOS_HASH:
            raise ValueError(f"Algoritmo '{algorithm}' não suportado. Use: {ALGORITMOS_HASH}")

        self.algorithm = algorithm
        self.block_size = block_size

    def calculate_hash(self, filepath: Path) -> str:
        """Calcula o hash de um arquivo.

        Args:
            filepath: Caminho do arquivo.

        Returns:
            Hash hexadecimal do arquivo.

        Raises:
            FileNotFoundError: Se o arquivo não existir.
            IOError: Se houver erro ao ler o arquivo.
        """
        if not filepath.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {filepath}")

        hash_func = getattr(hashlib, self.algorithm)
        h = hash_func()

        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(self.block_size), b''):
                h.update(block)

        return h.hexdigest()

    def scan_directory(
        self,
        directory: Path,
        extensions: List[str] = None
    ) -> Iterator[Tuple[str, Path]]:
        """Escaneia um diretório procurando arquivos relevantes.

        Args:
            directory: Diretório a escanear.
            extensions: Lista de extensões a procurar. Se None, usa EXTENSOES_RELEVANTES.

        Yields:
            Tuplas (nome_arquivo, caminho_completo).

        Raises:
            NotADirectoryError: Se o caminho não for um diretório.
        """
        if not directory.is_dir():
            raise NotADirectoryError(f"'{directory}' não é um diretório")

        if extensions is None:
            extensions = EXTENSOES_RELEVANTES

        # Converter extensões para lowercase para comparação case-insensitive
        extensions = [ext.lower() for ext in extensions]

        for root, _, files in os.walk(directory):
            for filename in files:
                if any(filename.lower().endswith(ext) for ext in extensions):
                    filepath = Path(root) / filename
                    yield filename, filepath

    def analyze_file(self, filepath: Path, vt_link_generator=None) -> FileAnalysisResult:
        """Analisa um arquivo calculando seu hash.

        Args:
            filepath: Caminho do arquivo a analisar.
            vt_link_generator: Função opcional para gerar link do VirusTotal.

        Returns:
            Objeto FileAnalysisResult com os resultados da análise.
        """
        filename = filepath.name

        try:
            hash_value = self.calculate_hash(filepath)
            vt_link = ""

            if vt_link_generator:
                vt_link = vt_link_generator(hash_value)

            return FileAnalysisResult(
                filename=filename,
                filepath=str(filepath),
                hash_value=hash_value,
                algorithm=self.algorithm,
                vt_link=vt_link,
                status=DetectionStatus.PENDING
            )

        except Exception as e:
            return FileAnalysisResult(
                filename=filename,
                filepath=str(filepath),
                hash_value="",
                algorithm=self.algorithm,
                vt_link="",
                status=DetectionStatus.ERROR,
                error_message=str(e)
            )

    def analyze_directory(
        self,
        directory: Path,
        vt_link_generator=None,
        extensions: List[str] = None
    ) -> Iterator[FileAnalysisResult]:
        """Analisa todos os arquivos relevantes em um diretório.

        Args:
            directory: Diretório a analisar.
            vt_link_generator: Função opcional para gerar links do VirusTotal.
            extensions: Lista de extensões a procurar.

        Yields:
            Objetos FileAnalysisResult para cada arquivo analisado.
        """
        for filename, filepath in self.scan_directory(directory, extensions):
            yield self.analyze_file(filepath, vt_link_generator)


def generate_vt_link(hash_value: str) -> str:
    """Gera um link para verificação no VirusTotal.

    Args:
        hash_value: Hash do arquivo.

    Returns:
        URL para a página de detecção do arquivo no VirusTotal.
    """
    from urllib.parse import quote_plus
    from .config import VT_WEB_BASE
    return f"{VT_WEB_BASE}/{quote_plus(hash_value)}/detection"
