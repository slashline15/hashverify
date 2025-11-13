"""HashVerify - Verificador de Segurança de Arquivos.

Uma aplicação Python com interface gráfica para calcular hashes de arquivos
e verificar possíveis ameaças usando a API do VirusTotal.
"""

__version__ = "2.0.0"
__author__ = "slashline15"
__license__ = "MIT"

# Importação condicional da GUI (requer tkinter)
try:
    from .gui import HashVerifyApp
    __all__ = ["HashVerifyApp"]
except ImportError:
    # tkinter não disponível (ambiente headless)
    __all__ = []
