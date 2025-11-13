"""Modelos de dados do HashVerify."""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum


class DetectionStatus(Enum):
    """Status de detecção de malware."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"
    PENDING = "pending"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


@dataclass
class FileAnalysisResult:
    """Resultado da análise de um arquivo.

    Attributes:
        filename: Nome do arquivo.
        filepath: Caminho completo do arquivo.
        hash_value: Hash calculado do arquivo.
        algorithm: Algoritmo de hash usado.
        vt_link: Link para verificação no VirusTotal.
        status: Status da detecção.
        malicious_count: Número de detecções maliciosas.
        suspicious_count: Número de detecções suspeitas.
        total_engines: Total de engines que analisaram.
        detected_name: Nome detectado do arquivo (se disponível).
        error_message: Mensagem de erro (se houver).
        raw_data: Dados brutos da API (opcional).
    """

    filename: str
    filepath: str
    hash_value: str
    algorithm: str
    vt_link: str
    status: DetectionStatus = DetectionStatus.PENDING
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    detected_name: Optional[str] = None
    error_message: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = field(default=None, repr=False)

    @property
    def is_threat(self) -> bool:
        """Verifica se o arquivo é uma ameaça.

        Returns:
            True se o arquivo for malicioso ou suspeito.
        """
        return self.status in (DetectionStatus.MALICIOUS, DetectionStatus.SUSPICIOUS)

    @property
    def detection_ratio(self) -> str:
        """Retorna a razão de detecção formatada.

        Returns:
            String no formato "X/Y" onde X é detecções e Y é total.
        """
        detections = self.malicious_count + self.suspicious_count
        return f"{detections}/{self.total_engines}"

    @property
    def detection_percentage(self) -> float:
        """Calcula a porcentagem de detecção.

        Returns:
            Porcentagem de detecção (0-100).
        """
        if self.total_engines == 0:
            return 0.0
        detections = self.malicious_count + self.suspicious_count
        return (detections / self.total_engines) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Converte o resultado para dicionário.

        Returns:
            Dicionário com os dados do resultado.
        """
        return {
            'filename': self.filename,
            'filepath': self.filepath,
            'hash': self.hash_value,
            'algorithm': self.algorithm,
            'vt_link': self.vt_link,
            'status': self.status.value,
            'malicious_count': self.malicious_count,
            'suspicious_count': self.suspicious_count,
            'total_engines': self.total_engines,
            'detected_name': self.detected_name,
            'detection_ratio': self.detection_ratio,
            'detection_percentage': round(self.detection_percentage, 2),
            'error_message': self.error_message
        }


@dataclass
class VirusTotalQuota:
    """Informações de quota da API do VirusTotal.

    Attributes:
        allowed: Número de requisições permitidas.
        used: Número de requisições usadas.
    """

    allowed: int
    used: int

    @property
    def remaining(self) -> int:
        """Calcula requisições restantes.

        Returns:
            Número de requisições restantes.
        """
        return max(0, self.allowed - self.used)

    @property
    def percentage_used(self) -> float:
        """Calcula porcentagem de quota usada.

        Returns:
            Porcentagem usada (0-100).
        """
        if self.allowed == 0:
            return 0.0
        return (self.used / self.allowed) * 100

    def __str__(self) -> str:
        """Representação em string da quota.

        Returns:
            String formatada com informações da quota.
        """
        return f"{self.used}/{self.allowed} usadas ({self.remaining} restantes)"
