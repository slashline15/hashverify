"""Módulo para integração com a API do VirusTotal."""

import time
from typing import Optional, Dict, Any
from pathlib import Path

import requests

from .config import (
    VT_FILES_ENDPOINT,
    VT_USERS_ENDPOINT,
    MAX_FILE_SIZE,
    DEFAULT_RATE_LIMIT
)
from .models import FileAnalysisResult, DetectionStatus, VirusTotalQuota


class VirusTotalAPI:
    """Cliente para a API do VirusTotal.

    Attributes:
        api_key: Chave de API do VirusTotal.
        rate_limit: Número de requisições por minuto.
        cache: Cache de resultados para evitar consultas repetidas.
        last_request_time: Timestamp da última requisição.
    """

    def __init__(self, api_key: str, rate_limit: int = DEFAULT_RATE_LIMIT) -> None:
        """Inicializa o cliente da API.

        Args:
            api_key: Chave de API do VirusTotal.
            rate_limit: Requisições por minuto permitidas.
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.last_request_time: float = 0.0

    def _get_headers(self) -> Dict[str, str]:
        """Retorna os headers para requisições.

        Returns:
            Dicionário com os headers HTTP.
        """
        return {"x-apikey": self.api_key}

    def _wait_rate_limit(self) -> float:
        """Aguarda o tempo necessário para respeitar o rate limit.

        Returns:
            Tempo esperado em segundos.
        """
        if self.last_request_time == 0:
            return 0.0

        elapsed = time.time() - self.last_request_time
        min_interval = 60.0 / self.rate_limit

        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            time.sleep(wait_time)
            return wait_time

        return 0.0

    def test_connection(self) -> tuple[bool, Optional[VirusTotalQuota], Optional[str]]:
        """Testa a conexão com a API.

        Returns:
            Tupla (sucesso, quota_info, mensagem_erro).
        """
        try:
            response = requests.get(VT_USERS_ENDPOINT, headers=self._get_headers())

            if response.status_code == 200:
                data = response.json()
                quota = None

                if "data" in data and "attributes" in data["data"]:
                    attrs = data["data"]["attributes"]
                    if "quotas" in attrs and "api_requests_daily" in attrs["quotas"]:
                        daily = attrs["quotas"]["api_requests_daily"]
                        if "allowed" in daily and "used" in daily:
                            quota = VirusTotalQuota(
                                allowed=daily["allowed"],
                                used=daily["used"]
                            )

                return True, quota, None
            else:
                return False, None, f"Erro {response.status_code}: {response.text}"

        except Exception as e:
            return False, None, str(e)

    def check_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Verifica um hash no VirusTotal.

        Args:
            hash_value: Hash a verificar.

        Returns:
            Dicionário com os resultados ou None se não encontrado.
        """
        # Verificar cache
        if hash_value in self.cache:
            return self.cache[hash_value]

        # Respeitar rate limit
        self._wait_rate_limit()

        try:
            url = f"{VT_FILES_ENDPOINT}/{hash_value}"
            response = requests.get(url, headers=self._get_headers())
            self.last_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                result = self._parse_response(data)
                self.cache[hash_value] = result
                return result
            elif response.status_code == 404:
                return None
            else:
                return {"error": f"Erro {response.status_code}: {response.text}"}

        except Exception as e:
            return {"error": str(e)}

    def _parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa a resposta da API.

        Args:
            data: Dados JSON da resposta.

        Returns:
            Dicionário com informações processadas.
        """
        result = {
            "status": DetectionStatus.UNKNOWN,
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "detected_name": None,
            "raw_data": data
        }

        try:
            if "data" in data and "attributes" in data["data"]:
                attrs = data["data"]["attributes"]

                # Estatísticas de análise
                if "last_analysis_stats" in attrs:
                    stats = attrs["last_analysis_stats"]
                    result["malicious"] = stats.get("malicious", 0)
                    result["suspicious"] = stats.get("suspicious", 0)
                    result["total"] = sum(stats.values())

                    # Determinar status
                    if result["malicious"] > 0:
                        result["status"] = DetectionStatus.MALICIOUS
                    elif result["suspicious"] > 0:
                        result["status"] = DetectionStatus.SUSPICIOUS
                    else:
                        result["status"] = DetectionStatus.CLEAN

                # Nome detectado
                if "meaningful_name" in attrs:
                    result["detected_name"] = attrs["meaningful_name"]
                elif "names" in attrs and attrs["names"]:
                    result["detected_name"] = attrs["names"][0]

        except Exception as e:
            result["error"] = str(e)

        return result

    def update_analysis_result(
        self,
        result: FileAnalysisResult,
        vt_data: Optional[Dict[str, Any]]
    ) -> FileAnalysisResult:
        """Atualiza um FileAnalysisResult com dados do VirusTotal.

        Args:
            result: Resultado da análise a atualizar.
            vt_data: Dados retornados pela API.

        Returns:
            Resultado atualizado.
        """
        if vt_data is None:
            result.status = DetectionStatus.NOT_FOUND
            return result

        if "error" in vt_data:
            result.status = DetectionStatus.ERROR
            result.error_message = vt_data["error"]
            return result

        result.status = vt_data.get("status", DetectionStatus.UNKNOWN)
        result.malicious_count = vt_data.get("malicious", 0)
        result.suspicious_count = vt_data.get("suspicious", 0)
        result.total_engines = vt_data.get("total", 0)
        result.detected_name = vt_data.get("detected_name")
        result.raw_data = vt_data.get("raw_data")

        return result

    def submit_file(self, filepath: Path) -> tuple[bool, Optional[str], Optional[str]]:
        """Submete um arquivo para análise no VirusTotal.

        Args:
            filepath: Caminho do arquivo a submeter.

        Returns:
            Tupla (sucesso, analysis_id, mensagem_erro).
        """
        if not filepath.exists():
            return False, None, "Arquivo não encontrado"

        file_size = filepath.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return False, None, f"Arquivo muito grande (>{MAX_FILE_SIZE / (1024*1024):.0f}MB)"

        # Respeitar rate limit
        self._wait_rate_limit()

        try:
            with open(filepath, 'rb') as f:
                files = {"file": (filepath.name, f)}
                response = requests.post(
                    VT_FILES_ENDPOINT,
                    files=files,
                    headers=self._get_headers()
                )
                self.last_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id")
                return True, analysis_id, None
            else:
                return False, None, f"Erro {response.status_code}: {response.text}"

        except Exception as e:
            return False, None, str(e)

    def clear_cache(self) -> None:
        """Limpa o cache de resultados."""
        self.cache.clear()

    def get_cached_result(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Obtém um resultado do cache.

        Args:
            hash_value: Hash a buscar no cache.

        Returns:
            Resultado cacheado ou None.
        """
        return self.cache.get(hash_value)
