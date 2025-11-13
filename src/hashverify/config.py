"""Configurações e constantes do HashVerify."""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

# Constantes
EXTENSOES_RELEVANTES = ['.exe', '.dll', '.bat', '.cmd', '.msi', '.vbs', '.ps1', '.jar', '.py']
ALGORITMOS_HASH = ['md5', 'sha1', 'sha256']
CONFIG_DIR = Path.home() / ".hashverify"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Limites da API
DEFAULT_RATE_LIMIT = 4  # Requisições por minuto
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB para upload direto

# URLs da API do VirusTotal
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_FILES_ENDPOINT = f"{VT_API_BASE}/files"
VT_USERS_ENDPOINT = f"{VT_API_BASE}/users/current"
VT_WEB_BASE = "https://www.virustotal.com/gui/file"


class ConfigManager:
    """Gerenciador de configurações do aplicativo.

    Attributes:
        config_file: Caminho para o arquivo de configuração.
        _config: Dicionário com as configurações carregadas.
    """

    def __init__(self, config_file: Optional[Path] = None) -> None:
        """Inicializa o gerenciador de configurações.

        Args:
            config_file: Caminho opcional para o arquivo de configuração.
                        Se não fornecido, usa o padrão.
        """
        self.config_file = config_file or CONFIG_FILE
        self._config: Dict[str, Any] = {}
        self._ensure_config_dir()
        self.load()

    def _ensure_config_dir(self) -> None:
        """Garante que o diretório de configuração existe."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> Dict[str, Any]:
        """Carrega as configurações do arquivo.

        Returns:
            Dicionário com as configurações carregadas.
        """
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._config = {}
        else:
            self._config = {}

        return self._config

    def save(self, config: Dict[str, Any]) -> None:
        """Salva as configurações no arquivo.

        Args:
            config: Dicionário com as configurações a salvar.

        Raises:
            IOError: Se houver erro ao salvar o arquivo.
        """
        self._config = config
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        """Obtém um valor de configuração.

        Args:
            key: Chave da configuração.
            default: Valor padrão se a chave não existir.

        Returns:
            Valor da configuração ou o valor padrão.
        """
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Define um valor de configuração.

        Args:
            key: Chave da configuração.
            value: Valor a definir.
        """
        self._config[key] = value

    def get_api_key(self) -> Optional[str]:
        """Obtém a API key do VirusTotal.

        Returns:
            API key ou None se não configurada.
        """
        return self.get('api_key')

    def set_api_key(self, api_key: str) -> None:
        """Define a API key do VirusTotal.

        Args:
            api_key: API key a salvar.
        """
        self.set('api_key', api_key)

    def get_rate_limit(self) -> int:
        """Obtém o limite de requisições por minuto.

        Returns:
            Limite de requisições.
        """
        return self.get('limite_rate', DEFAULT_RATE_LIMIT)

    def set_rate_limit(self, limit: int) -> None:
        """Define o limite de requisições por minuto.

        Args:
            limit: Novo limite de requisições.
        """
        self.set('limite_rate', limit)
