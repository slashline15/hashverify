"""Interface gráfica do HashVerify."""

import os
import threading
import webbrowser
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Callable
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import json

from .config import (
    ALGORITMOS_HASH,
    ConfigManager,
)
from .models import FileAnalysisResult, DetectionStatus
from .hash_calculator import HashCalculator, generate_vt_link
from .virustotal_api import VirusTotalAPI


class HashVerifyApp:
    """Aplicação principal com interface gráfica.

    Attributes:
        root: Janela principal do Tkinter.
        config_manager: Gerenciador de configurações.
        hash_calculator: Calculador de hashes.
        vt_api: Cliente da API do VirusTotal (opcional).
        results: Lista de resultados da análise.
        scanning: Flag indicando se há escaneamento em andamento.
    """

    def __init__(self, root: tk.Tk) -> None:
        """Inicializa a aplicação.

        Args:
            root: Janela principal do Tkinter.
        """
        self.root = root
        self.root.title("HashVerify - Verificador de Segurança de Arquivos")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)

        # Gerenciadores
        self.config_manager = ConfigManager()
        self.hash_calculator = HashCalculator()
        self.vt_api: Optional[VirusTotalAPI] = None

        # Variáveis de controle
        self.folder_path = tk.StringVar()
        self.algorithm = tk.StringVar(value="sha256")
        self.status_text = tk.StringVar(value="Pronto para iniciar")
        self.progress_var = tk.DoubleVar(value=0)
        self.api_key = tk.StringVar()
        self.use_api = tk.BooleanVar(value=False)
        self.rate_limit = tk.IntVar(value=4)
        self.show_key = tk.BooleanVar(value=False)

        # Estado da aplicação
        self.scanning = False
        self.results: List[FileAnalysisResult] = []

        # Carregar configurações salvas
        self._load_config()

        # Criar interface
        self._create_interface()

    def _load_config(self) -> None:
        """Carrega configurações salvas."""
        config = self.config_manager.load()
        api_key = self.config_manager.get_api_key()

        if api_key:
            self.api_key.set(api_key)
            self.use_api.set(True)

        rate_limit = self.config_manager.get_rate_limit()
        self.rate_limit.set(rate_limit)

    def _save_config(self) -> None:
        """Salva configurações atuais."""
        try:
            self.config_manager.set_api_key(self.api_key.get())
            self.config_manager.set_rate_limit(self.rate_limit.get())
            self.config_manager.save(self.config_manager._config)
            messagebox.showinfo("Sucesso", "Configurações salvas com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar configurações: {e}")

    def _create_interface(self) -> None:
        """Cria a interface gráfica completa."""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Seção de configuração
        self._create_config_section(main_frame)

        # Botões de ação
        self._create_action_buttons(main_frame)

        # Barra de progresso
        self._create_progress_bar(main_frame)

        # Tabela de resultados
        self._create_results_table(main_frame)

    def _create_config_section(self, parent: ttk.Frame) -> None:
        """Cria a seção de configurações.

        Args:
            parent: Frame pai.
        """
        config_frame = ttk.LabelFrame(parent, text="Configurações", padding=10)
        config_frame.pack(fill=tk.X, pady=5)

        # Seleção de pasta
        ttk.Label(config_frame, text="Pasta a verificar:").grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(config_frame, textvariable=self.folder_path, width=50).grid(
            row=0, column=1, sticky=tk.EW, padx=5, pady=5
        )
        ttk.Button(config_frame, text="Procurar...", command=self._select_folder).grid(
            row=0, column=2, sticky=tk.E, pady=5
        )

        # Algoritmo hash
        ttk.Label(config_frame, text="Algoritmo:").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        algo_combo = ttk.Combobox(
            config_frame,
            textvariable=self.algorithm,
            values=ALGORITMOS_HASH,
            state="readonly",
            width=10
        )
        algo_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Separador
        ttk.Separator(config_frame, orient='horizontal').grid(
            row=2, column=0, columnspan=3, sticky=tk.EW, pady=8
        )

        # Configuração da API
        self._create_api_config(config_frame)

        # Configurar grid
        config_frame.columnconfigure(1, weight=1)

    def _create_api_config(self, parent: ttk.Frame) -> None:
        """Cria a seção de configuração da API.

        Args:
            parent: Frame pai.
        """
        # Checkbox para ativar API
        ttk.Checkbutton(
            parent,
            text="Usar API VirusTotal",
            variable=self.use_api,
            command=self._toggle_api_config
        ).grid(row=3, column=0, sticky=tk.W, pady=5)

        # Frame para API key
        self.api_frame = ttk.Frame(parent)
        self.api_frame.grid(row=4, column=0, columnspan=3, sticky=tk.EW, pady=5)

        ttk.Label(self.api_frame, text="API Key:").grid(row=0, column=0, sticky=tk.W)
        self.api_key_entry = ttk.Entry(
            self.api_frame, textvariable=self.api_key, width=40, show="*"
        )
        self.api_key_entry.grid(row=0, column=1, sticky=tk.W, padx=5)

        # Botão para mostrar/ocultar key
        ttk.Checkbutton(
            self.api_frame,
            text="Mostrar",
            variable=self.show_key,
            command=self._toggle_show_key
        ).grid(row=0, column=2, sticky=tk.W)

        # Botões de ação da API
        ttk.Button(self.api_frame, text="Salvar", command=self._save_config).grid(
            row=0, column=3, padx=5
        )
        ttk.Button(self.api_frame, text="Testar API", command=self._test_api).grid(
            row=0, column=4, padx=5
        )

        # Limite de taxa
        ttk.Label(self.api_frame, text="Solicitações/min:").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        ttk.Spinbox(
            self.api_frame, from_=1, to=10, width=3, textvariable=self.rate_limit
        ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Atualizar visibilidade
        self._toggle_api_config()

    def _create_action_buttons(self, parent: ttk.Frame) -> None:
        """Cria os botões de ação.

        Args:
            parent: Frame pai.
        """
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=10)

        buttons = [
            ("Iniciar Verificação", self._start_scan),
            ("Parar", self._stop_scan),
            ("Exportar CSV", lambda: self._export_report("csv")),
            ("Exportar JSON", lambda: self._export_report("json")),
            ("Verificar Selecionados", self._check_selected_vt),
        ]

        for text, command in buttons:
            ttk.Button(action_frame, text=text, command=command).pack(
                side=tk.LEFT, padx=5
            )

    def _create_progress_bar(self, parent: ttk.Frame) -> None:
        """Cria a barra de progresso.

        Args:
            parent: Frame pai.
        """
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X, pady=5)

        ttk.Label(progress_frame, textvariable=self.status_text).pack(
            side=tk.LEFT, padx=5
        )
        self.progress_bar = ttk.Progressbar(
            progress_frame, variable=self.progress_var, maximum=100
        )
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)

    def _create_results_table(self, parent: ttk.Frame) -> None:
        """Cria a tabela de resultados.

        Args:
            parent: Frame pai.
        """
        result_frame = ttk.LabelFrame(parent, text="Resultados", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Colunas da tabela
        columns = ("arquivo", "caminho", "hash", "deteccoes")
        self.result_table = ttk.Treeview(result_frame, columns=columns, show="headings")

        # Configurar colunas
        self.result_table.heading("arquivo", text="Arquivo")
        self.result_table.heading("caminho", text="Caminho")
        self.result_table.heading("hash", text="Hash")
        self.result_table.heading("deteccoes", text="Detecções")

        self.result_table.column("arquivo", width=100)
        self.result_table.column("caminho", width=200)
        self.result_table.column("hash", width=250)
        self.result_table.column("deteccoes", width=130)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            result_frame, orient=tk.VERTICAL, command=self.result_table.yview
        )
        self.result_table.configure(yscroll=scrollbar.set)

        # Empacotar
        self.result_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bindings
        self.result_table.bind("<Button-3>", self._show_context_menu)
        self.result_table.bind("<Double-1>", self._open_vt_link)

        # Menu de contexto
        self._create_context_menu()

    def _create_context_menu(self) -> None:
        """Cria o menu de contexto."""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copiar Hash", command=self._copy_hash)
        self.context_menu.add_command(
            label="Verificar no VirusTotal", command=lambda: self._open_vt_link()
        )
        self.context_menu.add_command(
            label="Detalhes da Análise", command=self._show_vt_details
        )
        self.context_menu.add_command(
            label="Submeter Arquivo ao VirusTotal", command=self._submit_file_vt
        )
        self.context_menu.add_command(
            label="Abrir Localização do Arquivo", command=self._open_file_location
        )

    # Métodos de callback para ações

    def _select_folder(self) -> None:
        """Abre diálogo para selecionar pasta."""
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    def _toggle_api_config(self) -> None:
        """Mostra/oculta configurações da API."""
        if self.use_api.get():
            self.api_frame.grid()
        else:
            self.api_frame.grid_remove()

    def _toggle_show_key(self) -> None:
        """Mostra/oculta a API key."""
        if self.show_key.get():
            self.api_key_entry.config(show="")
        else:
            self.api_key_entry.config(show="*")

    def _test_api(self) -> None:
        """Testa a conexão com a API."""
        api_key = self.api_key.get()
        if not api_key:
            messagebox.showerror("Erro", "API Key não definida")
            return

        self.status_text.set("Testando API VirusTotal...")
        threading.Thread(target=self._test_api_thread, daemon=True).start()

    def _test_api_thread(self) -> None:
        """Thread para testar a API."""
        api_key = self.api_key.get()
        rate_limit = self.rate_limit.get()

        vt_api = VirusTotalAPI(api_key, rate_limit)
        success, quota, error = vt_api.test_connection()

        if success:
            quota_info = f"\n\n{quota}" if quota else ""
            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Sucesso", f"API VirusTotal conectada com sucesso!{quota_info}"
                )
            )
            self.root.after(0, lambda: self.status_text.set("API VirusTotal: Conectada"))
        else:
            self.root.after(
                0,
                lambda: messagebox.showerror("Erro", f"Erro ao conectar com a API:\n{error}")
            )
            self.root.after(0, lambda: self.status_text.set("API VirusTotal: Erro"))

    def _start_scan(self) -> None:
        """Inicia o escaneamento de arquivos."""
        folder = self.folder_path.get()
        if not folder:
            messagebox.showerror("Erro", "Selecione uma pasta para verificar")
            return

        if self.scanning:
            messagebox.showinfo("Aviso", "Um escaneamento já está em andamento")
            return

        # Limpar resultados anteriores
        self.result_table.delete(*self.result_table.get_children())
        self.results.clear()

        # Atualizar calculador com algoritmo selecionado
        self.hash_calculator = HashCalculator(self.algorithm.get())

        # Inicializar API se necessário
        if self.use_api.get() and self.api_key.get():
            self.vt_api = VirusTotalAPI(self.api_key.get(), self.rate_limit.get())
        else:
            self.vt_api = None

        # Iniciar escaneamento em thread separada
        self.scanning = True
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self) -> None:
        """Thread para executar o escaneamento."""
        folder = Path(self.folder_path.get())

        self.status_text.set("Coletando arquivos...")
        self.progress_var.set(0)

        try:
            # Coletar arquivos
            files = list(self.hash_calculator.scan_directory(folder))
            total_files = len(files)

            if total_files == 0:
                self.status_text.set("Nenhum arquivo relevante encontrado")
                self.scanning = False
                return

            # Processar arquivos
            for i, (filename, filepath) in enumerate(files):
                if not self.scanning:
                    break

                self.status_text.set(f"Verificando ({i+1}/{total_files}): {filename}")
                self.progress_var.set((i / total_files) * 100)

                # Analisar arquivo
                result = self.hash_calculator.analyze_file(filepath, generate_vt_link)
                self.results.append(result)

                # Adicionar à tabela
                self.root.after(0, lambda r=result: self._add_result_to_table(r))

                # Se estiver usando API, verificar no VirusTotal
                if self.vt_api and result.status != DetectionStatus.ERROR:
                    threading.Thread(
                        target=self._check_hash_vt,
                        args=(result,),
                        daemon=True
                    ).start()

            if self.scanning:
                self.status_text.set(
                    f"Verificação concluída: {len(self.results)} arquivos processados"
                )
                self.progress_var.set(100)
            else:
                self.status_text.set("Verificação interrompida")

        except Exception as e:
            self.root.after(
                0, lambda: messagebox.showerror("Erro", f"Erro durante escaneamento: {e}")
            )
            self.status_text.set(f"Erro: {e}")

        finally:
            self.scanning = False

    def _stop_scan(self) -> None:
        """Para o escaneamento em andamento."""
        if self.scanning:
            self.scanning = False
            self.status_text.set("Cancelando verificação...")

    def _add_result_to_table(self, result: FileAnalysisResult) -> str:
        """Adiciona um resultado à tabela.

        Args:
            result: Resultado da análise.

        Returns:
            ID do item na tabela.
        """
        status_text = self._get_status_text(result)

        item_id = self.result_table.insert(
            "",
            tk.END,
            values=(result.filename, result.filepath, result.hash_value, status_text)
        )

        # Aplicar cor se for uma detecção
        if result.is_threat:
            color = "red" if result.status == DetectionStatus.MALICIOUS else "orange"
            self.result_table.tag_configure(color, foreground=color)
            self.result_table.item(item_id, tags=(color,))

        return item_id

    def _get_status_text(self, result: FileAnalysisResult) -> str:
        """Retorna texto do status para exibição.

        Args:
            result: Resultado da análise.

        Returns:
            Texto formatado do status.
        """
        if result.status == DetectionStatus.ERROR:
            return "Erro"
        elif result.status == DetectionStatus.NOT_FOUND:
            return "Não encontrado"
        elif result.status == DetectionStatus.PENDING:
            return "Verificar" if not self.use_api.get() else "Pendente"
        elif result.status == DetectionStatus.CLEAN:
            return f"✅ 0/{result.total_engines}"
        elif result.status in (DetectionStatus.SUSPICIOUS, DetectionStatus.MALICIOUS):
            detections = result.malicious_count + result.suspicious_count
            return f"⚠️ {detections}/{result.total_engines}"
        else:
            return "Desconhecido"

    def _check_hash_vt(self, result: FileAnalysisResult) -> None:
        """Verifica um hash no VirusTotal.

        Args:
            result: Resultado com o hash a verificar.
        """
        if not self.vt_api:
            return

        vt_data = self.vt_api.check_hash(result.hash_value)
        self.vt_api.update_analysis_result(result, vt_data)

        # Atualizar a tabela
        self.root.after(0, lambda: self._update_result_in_table(result))

    def _update_result_in_table(self, result: FileAnalysisResult) -> None:
        """Atualiza um resultado na tabela.

        Args:
            result: Resultado atualizado.
        """
        # Encontrar o item na tabela
        for item in self.result_table.get_children():
            values = self.result_table.item(item, "values")
            if values[2] == result.hash_value:  # Comparar pelo hash
                status_text = self._get_status_text(result)
                self.result_table.item(
                    item, values=(values[0], values[1], values[2], status_text)
                )

                # Atualizar cor
                if result.is_threat:
                    color = "red" if result.status == DetectionStatus.MALICIOUS else "orange"
                    self.result_table.tag_configure(color, foreground=color)
                    self.result_table.item(item, tags=(color,))
                break

    def _export_report(self, format_type: str) -> None:
        """Exporta o relatório.

        Args:
            format_type: Formato de exportação ('csv' ou 'json').
        """
        if not self.results:
            messagebox.showinfo("Aviso", "Nenhum dado para exportar")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        if format_type == "csv":
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv")],
                initialfile=f"relatorio_hash_{timestamp}.csv"
            )
            if filename:
                self._export_csv(filename)

        elif format_type == "json":
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json")],
                initialfile=f"relatorio_hash_{timestamp}.json"
            )
            if filename:
                self._export_json(filename)

    def _export_csv(self, filename: str) -> None:
        """Exporta para CSV.

        Args:
            filename: Caminho do arquivo a criar.
        """
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Cabeçalhos
                headers = ["Nome", "Caminho", "Hash", "Algoritmo", "Link VirusTotal"]
                if self.use_api.get():
                    headers.extend(["Status", "Detecções Maliciosas", "Detecções Suspeitas", "Total Engines"])

                writer.writerow(headers)

                # Dados
                for result in self.results:
                    row = [
                        result.filename,
                        result.filepath,
                        result.hash_value,
                        result.algorithm,
                        result.vt_link
                    ]

                    if self.use_api.get():
                        row.extend([
                            result.status.value,
                            result.malicious_count,
                            result.suspicious_count,
                            result.total_engines
                        ])

                    writer.writerow(row)

            self.status_text.set(f"Relatório CSV exportado: {filename}")
            messagebox.showinfo("Sucesso", f"Relatório exportado para:\n{filename}")

        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar CSV: {e}")

    def _export_json(self, filename: str) -> None:
        """Exporta para JSON.

        Args:
            filename: Caminho do arquivo a criar.
        """
        try:
            data = [result.to_dict() for result in self.results]

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            self.status_text.set(f"Relatório JSON exportado: {filename}")
            messagebox.showinfo("Sucesso", f"Relatório exportado para:\n{filename}")

        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar JSON: {e}")

    # Métodos do menu de contexto

    def _show_context_menu(self, event: tk.Event) -> None:
        """Mostra o menu de contexto.

        Args:
            event: Evento do mouse.
        """
        item = self.result_table.identify_row(event.y)
        if item:
            self.result_table.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _copy_hash(self) -> None:
        """Copia o hash selecionado para a área de transferência."""
        selection = self.result_table.selection()
        if selection:
            hash_value = self.result_table.item(selection[0], "values")[2]
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_value)
            self.status_text.set("Hash copiado para a área de transferência")

    def _open_vt_link(self, event: Optional[tk.Event] = None) -> None:
        """Abre o link do VirusTotal no navegador.

        Args:
            event: Evento do mouse (opcional).
        """
        if event:
            item = self.result_table.identify_row(event.y)
            if item:
                self.result_table.selection_set(item)
            else:
                return

        selection = self.result_table.selection()
        if selection:
            values = self.result_table.item(selection[0], "values")
            hash_value = values[2]

            if not hash_value or hash_value.startswith("Erro"):
                messagebox.showerror("Erro", "Não é possível abrir este arquivo")
                return

            link = generate_vt_link(hash_value)
            webbrowser.open(link)
            self.status_text.set(f"Abrindo {values[0]} no VirusTotal")

    def _show_vt_details(self) -> None:
        """Mostra detalhes da análise do VirusTotal."""
        selection = self.result_table.selection()
        if not selection:
            return

        values = self.result_table.item(selection[0], "values")
        hash_value = values[2]

        # Encontrar o resultado correspondente
        result = None
        for r in self.results:
            if r.hash_value == hash_value:
                result = r
                break

        if not result or result.status == DetectionStatus.PENDING:
            messagebox.showinfo("Aviso", "Resultado ainda não disponível")
            return

        # Criar janela de detalhes
        self._create_details_window(result)

    def _create_details_window(self, result: FileAnalysisResult) -> None:
        """Cria janela com detalhes da análise.

        Args:
            result: Resultado da análise.
        """
        details_window = tk.Toplevel(self.root)
        details_window.title("Detalhes VirusTotal")
        details_window.geometry("400x300")
        details_window.minsize(400, 300)

        main_frame = ttk.Frame(details_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Informações do arquivo
        info_frame = ttk.LabelFrame(main_frame, text="Informações do Arquivo", padding=10)
        info_frame.pack(fill=tk.X, pady=5)

        ttk.Label(info_frame, text=f"Nome: {result.filename}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Hash: {result.hash_value}").pack(anchor=tk.W)

        if result.detected_name:
            ttk.Label(info_frame, text=f"Nome detectado: {result.detected_name}").pack(
                anchor=tk.W
            )

        # Estatísticas
        if result.total_engines > 0:
            stats_frame = ttk.LabelFrame(
                main_frame, text="Estatísticas de Detecção", padding=10
            )
            stats_frame.pack(fill=tk.X, pady=5)

            ttk.Label(
                stats_frame,
                text=f"Maliciosos: {result.malicious_count} ({result.malicious_count/result.total_engines*100:.1f}%)"
            ).pack(anchor=tk.W)

            ttk.Label(
                stats_frame,
                text=f"Suspeitos: {result.suspicious_count} ({result.suspicious_count/result.total_engines*100:.1f}%)"
            ).pack(anchor=tk.W)

            clean = result.total_engines - result.malicious_count - result.suspicious_count
            ttk.Label(
                stats_frame,
                text=f"Limpo: {clean} ({clean/result.total_engines*100:.1f}%)"
            ).pack(anchor=tk.W)

            ttk.Label(stats_frame, text=f"Total de engines: {result.total_engines}").pack(
                anchor=tk.W
            )

        # Botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            button_frame,
            text="Abrir no VirusTotal",
            command=lambda: webbrowser.open(result.vt_link)
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Fechar", command=details_window.destroy).pack(
            side=tk.RIGHT, padx=5
        )

    def _open_file_location(self) -> None:
        """Abre a localização do arquivo no explorer."""
        selection = self.result_table.selection()
        if not selection:
            return

        filepath = self.result_table.item(selection[0], "values")[1]
        directory = os.path.dirname(filepath)

        if not os.path.exists(directory):
            messagebox.showerror("Erro", "Diretório não encontrado")
            return

        try:
            if os.name == 'nt':  # Windows
                os.startfile(directory)
            elif os.name == 'posix':  # macOS e Linux
                try:
                    os.system(f'xdg-open "{directory}"')
                except:
                    try:
                        os.system(f'open "{directory}"')
                    except:
                        messagebox.showerror("Erro", "Não foi possível abrir o diretório")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao abrir diretório: {e}")

    def _check_selected_vt(self) -> None:
        """Verifica os itens selecionados no VirusTotal."""
        selection = self.result_table.selection()
        if not selection:
            messagebox.showinfo("Aviso", "Nenhum item selecionado")
            return

        if not self.use_api.get():
            response = messagebox.askyesno(
                "API não ativada",
                "A API do VirusTotal não está ativada. Deseja ativá-la agora?"
            )
            if response:
                self.use_api.set(True)
                self._toggle_api_config()
            else:
                return

        if not self.api_key.get():
            messagebox.showerror("Erro", "API Key não definida")
            return

        # Inicializar API se necessário
        if not self.vt_api:
            self.vt_api = VirusTotalAPI(self.api_key.get(), self.rate_limit.get())

        # Verificar cada item selecionado
        for item in selection:
            values = self.result_table.item(item, "values")
            hash_value = values[2]

            # Encontrar o resultado correspondente
            for result in self.results:
                if result.hash_value == hash_value:
                    threading.Thread(
                        target=self._check_hash_vt,
                        args=(result,),
                        daemon=True
                    ).start()
                    break

    def _submit_file_vt(self) -> None:
        """Submete o arquivo selecionado ao VirusTotal."""
        selection = self.result_table.selection()
        if not selection:
            messagebox.showinfo("Aviso", "Nenhum item selecionado")
            return

        if not self.use_api.get() or not self.api_key.get():
            messagebox.showerror("Erro", "API Key não definida ou API não ativada")
            return

        values = self.result_table.item(selection[0], "values")
        filepath = Path(values[1])

        if not filepath.exists():
            messagebox.showerror("Erro", "Arquivo não encontrado")
            return

        # Confirmar upload
        confirm = messagebox.askokcancel(
            "Confirmar Upload",
            f"Deseja enviar o arquivo '{values[0]}' para o VirusTotal?\n\n"
            "Nota: O arquivo será enviado para os servidores do VirusTotal e "
            "ficará disponível publicamente."
        )

        if not confirm:
            return

        # Inicializar API se necessário
        if not self.vt_api:
            self.vt_api = VirusTotalAPI(self.api_key.get(), self.rate_limit.get())

        # Submeter em thread separada
        threading.Thread(
            target=self._submit_file_thread,
            args=(filepath, values[2]),
            daemon=True
        ).start()

    def _submit_file_thread(self, filepath: Path, hash_value: str) -> None:
        """Thread para submeter arquivo.

        Args:
            filepath: Caminho do arquivo.
            hash_value: Hash do arquivo.
        """
        success, analysis_id, error = self.vt_api.submit_file(filepath)

        if success:
            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Sucesso",
                    f"Arquivo enviado com sucesso!\nID da análise: {analysis_id}"
                )
            )

            # Aguardar um pouco e verificar novamente
            import time
            time.sleep(5)

            # Encontrar o resultado e verificar novamente
            for result in self.results:
                if result.hash_value == hash_value:
                    self._check_hash_vt(result)
                    break
        else:
            self.root.after(
                0, lambda: messagebox.showerror("Erro", f"Erro ao enviar arquivo:\n{error}")
            )


def main() -> None:
    """Função principal para executar a aplicação."""
    root = tk.Tk()
    app = HashVerifyApp(root)
    root.mainloop()
