import hashlib
import os
import urllib.parse
import webbrowser
import threading
import time
import requests
from datetime import datetime
from tkinter import Tk, filedialog, messagebox
import tkinter as tk
from tkinter import ttk
import csv
import json

# Configurações
EXTENSOES_RELEVANTES = ['.exe', '.dll', '.bat', '.cmd', '.msi', '.vbs', '.ps1', '.jar', '.py']
ALGORITMOS_HASH = ['md5', 'sha1', 'sha256']

class HashVerifyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HashVerify - Verificador de Segurança de Arquivos")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Variáveis de controle
        self.pasta_selecionada = tk.StringVar()
        self.algoritmo = tk.StringVar(value="sha256")
        self.status = tk.StringVar(value="Pronto para iniciar")
        self.progresso = tk.DoubleVar(value=0)
        self.escaneamento_em_andamento = False
        self.relatorio = []
        self.api_key = tk.StringVar()
        self.usar_api = tk.BooleanVar(value=False)
        self.limite_rate = tk.IntVar(value=4)  # Requisições por minuto
        self.tempo_ultima_req = 0
        self.cache_resultados = {}  # Cache para evitar consultas repetidas
        
        # Carregar API key se existir
        self.carregar_config()
        
        # Interface principal
        self.criar_interface()
    
    def criar_interface(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Seção de configuração
        config_frame = ttk.LabelFrame(main_frame, text="Configurações", padding=10)
        config_frame.pack(fill=tk.X, pady=5)
        
        # Seleção de pasta
        ttk.Label(config_frame, text="Pasta a verificar:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(config_frame, textvariable=self.pasta_selecionada, width=50).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Button(config_frame, text="Procurar...", command=self.selecionar_pasta).grid(row=0, column=2, sticky=tk.E, pady=5)
        
        # Algoritmo hash
        ttk.Label(config_frame, text="Algoritmo:").grid(row=1, column=0, sticky=tk.W, pady=5)
        algoritmo_combo = ttk.Combobox(config_frame, textvariable=self.algoritmo, values=ALGORITMOS_HASH, state="readonly", width=10)
        algoritmo_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Configuração da API VirusTotal
        ttk.Separator(config_frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky=tk.EW, pady=8)
        
        # Checkbox para ativar API
        ttk.Checkbutton(config_frame, text="Usar API VirusTotal", variable=self.usar_api, 
                      command=self.toggle_api_config).grid(row=3, column=0, sticky=tk.W, pady=5)
        
        # Frame para API key (inicialmente oculto se não estiver ativado)
        self.api_frame = ttk.Frame(config_frame)
        self.api_frame.grid(row=4, column=0, columnspan=3, sticky=tk.EW, pady=5)
        ttk.Label(self.api_frame, text="API Key:").grid(row=0, column=0, sticky=tk.W)
        self.api_key_entry = ttk.Entry(self.api_frame, textvariable=self.api_key, width=40, show="*")
        self.api_key_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Botão para mostrar/ocultar API key
        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.api_frame, text="Mostrar", variable=self.show_key_var, 
                      command=self.toggle_show_key).grid(row=0, column=2, sticky=tk.W)
        
        # Botões para salvar/testar API
        ttk.Button(self.api_frame, text="Salvar", command=self.salvar_config).grid(row=0, column=3, padx=5)
        ttk.Button(self.api_frame, text="Testar API", command=self.testar_api).grid(row=0, column=4, padx=5)
        
        # Limite de taxa (opcional)
        ttk.Label(self.api_frame, text="Solicitações/min:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(self.api_frame, from_=1, to=10, width=3, textvariable=self.limite_rate).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Atualizar visibilidade do frame da API
        self.toggle_api_config()
        
        # Botões de ação
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(action_frame, text="Iniciar Verificação", command=self.iniciar_verificacao).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Parar", command=self.parar_verificacao).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Exportar CSV", command=lambda: self.exportar_relatorio("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Exportar JSON", command=lambda: self.exportar_relatorio("json")).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Verificar Selecionados", command=self.verificar_selecionados_vt).pack(side=tk.LEFT, padx=5)
        
        # Barra de progresso
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(progress_frame, textvariable=self.status).pack(side=tk.LEFT, padx=5)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progresso, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)
        
        # Exibição de resultados
        result_frame = ttk.LabelFrame(main_frame, text="Resultados", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Tabela de resultados
        columns = ("arquivo", "caminho", "hash", "acao")
        self.result_table = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        # Configuração das colunas
        self.result_table.heading("arquivo", text="Arquivo")
        self.result_table.heading("caminho", text="Caminho")
        self.result_table.heading("hash", text="Hash")
        self.result_table.heading("acao", text="Detecções")
        
        self.result_table.column("arquivo", width=100)
        self.result_table.column("caminho", width=200)
        self.result_table.column("hash", width=250)
        self.result_table.column("acao", width=130)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_table.yview)
        self.result_table.configure(yscroll=scrollbar.set)
        
        # Empacotamento da tabela e da scrollbar
        self.result_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Vincular menu de contexto
        self.result_table.bind("<Button-3>", self.mostrar_menu_contexto)
        self.result_table.bind("<Double-1>", self.abrir_link_virustotal)
        
        # Menu de contexto
        self.menu_contexto = tk.Menu(self.root, tearoff=0)
        self.menu_contexto.add_command(label="Copiar Hash", command=self.copiar_hash)
        self.menu_contexto.add_command(label="Verificar no VirusTotal", command=self.abrir_link_virustotal)
        self.menu_contexto.add_command(label="Detalhes da Análise", command=self.mostrar_detalhes_vt)
        self.menu_contexto.add_command(label="Submeter Arquivo ao VirusTotal", command=self.submeter_arquivo_vt)
        self.menu_contexto.add_command(label="Abrir Localização do Arquivo", command=self.abrir_localizacao)
    
    def selecionar_pasta(self):
        pasta = filedialog.askdirectory()
        if pasta:
            self.pasta_selecionada.set(pasta)
    
    def iniciar_verificacao(self):
        pasta = self.pasta_selecionada.get()
        if not pasta:
            messagebox.showerror("Erro", "Selecione uma pasta para verificar")
            return
        
        if self.escaneamento_em_andamento:
            messagebox.showinfo("Aviso", "Um escaneamento já está em andamento")
            return
        
        # Limpar resultados anteriores
        self.result_table.delete(*self.result_table.get_children())
        self.relatorio = []
        
        # Iniciar escaneamento em uma thread separada
        self.escaneamento_em_andamento = True
        threading.Thread(target=self.executar_verificacao, daemon=True).start()
    
    def executar_verificacao(self):
        pasta = self.pasta_selecionada.get()
        algoritmo = self.algoritmo.get()
        
        self.status.set("Coletando arquivos...")
        self.progresso.set(0)
        
        # Pré-calcular os arquivos para melhorar a exibição de progresso
        arquivos_para_verificar = []
        for raiz, _, arquivos in os.walk(pasta):
            for nome in arquivos:
                if any(nome.lower().endswith(ext) for ext in EXTENSOES_RELEVANTES):
                    caminho_arquivo = os.path.join(raiz, nome)
                    arquivos_para_verificar.append((nome, caminho_arquivo))
        
        total_arquivos = len(arquivos_para_verificar)
        if total_arquivos == 0:
            self.status.set("Nenhum arquivo relevante encontrado")
            self.escaneamento_em_andamento = False
            return
        
        # Processar os arquivos
        for i, (nome, caminho_arquivo) in enumerate(arquivos_para_verificar):
            if not self.escaneamento_em_andamento:
                break
                
            self.status.set(f"Verificando ({i+1}/{total_arquivos}): {nome}")
            self.progresso.set((i / total_arquivos) * 100)
            
            try:
                hash_valor = self.calcular_hash(caminho_arquivo, algoritmo)
                link_vt = self.gerar_link_virustotal(hash_valor, algoritmo)
                
                # Adicionar ao relatório
                resultado = (nome, caminho_arquivo, hash_valor, link_vt)
                self.relatorio.append(resultado)
                
                # Adicionar à tabela
                self.root.after(0, lambda r=resultado: self.adicionar_resultado_tabela(r))
                
            except Exception as e:
                erro = f"Erro: {str(e)}"
                resultado = (nome, caminho_arquivo, erro, "")
                self.relatorio.append(resultado)
                self.root.after(0, lambda r=resultado: self.adicionar_resultado_tabela(r))
        
        if self.escaneamento_em_andamento:
            self.status.set(f"Verificação concluída: {len(self.relatorio)} arquivos processados")
            self.progresso.set(100)
        else:
            self.status.set("Verificação interrompida")
        
        self.escaneamento_em_andamento = False
    
    def adicionar_resultado_tabela(self, resultado):
        nome, caminho, hash_valor, link = resultado
        
        if hash_valor.startswith("Erro:"):
            status = "Erro"
        elif not self.usar_api.get():
            status = "Verificar"
        else:
            # Se estamos usando a API, iniciar com "Pendente"
            status = "Pendente"
            # Iniciar a verificação do VirusTotal em uma thread separada
            threading.Thread(target=self.verificar_hash_virustotal, 
                           args=(hash_valor, self.result_table.insert("", tk.END, values=(nome, caminho, hash_valor, status))),
                           daemon=True).start()
            return
            
        # Se não estamos usando a API ou houve erro, adicionar diretamente
        self.result_table.insert("", tk.END, values=(nome, caminho, hash_valor, status))
    
    def parar_verificacao(self):
        if self.escaneamento_em_andamento:
            self.escaneamento_em_andamento = False
            self.status.set("Cancelando verificação...")
    
    def exportar_relatorio(self, formato):
        if not self.relatorio:
            messagebox.showinfo("Aviso", "Nenhum dado para exportar")
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        if formato == "csv":
            arquivo = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv")],
                initialfile=f"relatorio_hash_{timestamp}.csv"
            )
            if arquivo:
                self.exportar_csv(arquivo)
        
        elif formato == "json":
            arquivo = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json")],
                initialfile=f"relatorio_hash_{timestamp}.json"
            )
            if arquivo:
                self.exportar_json(arquivo)
    
    def exportar_csv(self, arquivo):
        try:
            with open(arquivo, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Cabeçalhos diferentes dependendo se a API está ativa
                if self.usar_api.get():
                    writer.writerow(["Nome", "Caminho", "Hash", "Link VirusTotal", "Status", "Detecções", "Total Scanners"])
                else:
                    writer.writerow(["Nome", "Caminho", "Hash", "Link VirusTotal"])
                
                for nome, caminho, hash_valor, link in self.relatorio:
                    if self.usar_api.get() and hash_valor in self.cache_resultados:
                        resultado_vt = self.cache_resultados[hash_valor]
                        detalhes = resultado_vt.get("detalhes", {})
                        writer.writerow([
                            nome, 
                            caminho, 
                            hash_valor, 
                            link,
                            resultado_vt["resultado"],
                            detalhes.get("malicious", 0) + detalhes.get("suspicious", 0),
                            detalhes.get("total", 0)
                        ])
                    else:
                        writer.writerow([nome, caminho, hash_valor, link])
            
            self.status.set(f"Relatório CSV exportado: {arquivo}")
            messagebox.showinfo("Exportação Concluída", f"Relatório exportado para:\n{arquivo}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar CSV: {str(e)}")
    
    def exportar_json(self, arquivo):
        try:
            dados_json = []
            for nome, caminho, hash_valor, link in self.relatorio:
                item = {
                    "nome": nome,
                    "caminho": caminho,
                    "hash": hash_valor,
                    "link_virustotal": link
                }
                
                # Adicionar dados da API se disponíveis
                if self.usar_api.get() and hash_valor in self.cache_resultados:
                    resultado_vt = self.cache_resultados[hash_valor]
                    item["resultado_vt"] = resultado_vt["resultado"]
                    item["detalhes_vt"] = resultado_vt["detalhes"]
                
                dados_json.append(item)
            
            with open(arquivo, 'w', encoding='utf-8') as f:
                json.dump(dados_json, f, ensure_ascii=False, indent=2)
            
            self.status.set(f"Relatório JSON exportado: {arquivo}")
            messagebox.showinfo("Exportação Concluída", f"Relatório exportado para:\n{arquivo}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar JSON: {str(e)}")
    
    def calcular_hash(self, arquivo, algoritmo='sha256'):
        hash_func = getattr(hashlib, algoritmo)
        h = hash_func()
        with open(arquivo, 'rb') as f:
            for bloco in iter(lambda: f.read(4096), b''):
                h.update(bloco)
        return h.hexdigest()
    
    def gerar_link_virustotal(self, hash_valor, algoritmo='sha256'):
        return f"https://www.virustotal.com/gui/file/{urllib.parse.quote_plus(hash_valor)}/detection"
        
    def toggle_api_config(self):
        if self.usar_api.get():
            self.api_frame.grid()
        else:
            self.api_frame.grid_remove()
            
    def toggle_show_key(self):
        if self.show_key_var.get():
            self.api_key_entry.config(show="")
        else:
            self.api_key_entry.config(show="*")
            
    def salvar_config(self):
        try:
            config = {
                "api_key": self.api_key.get(),
                "limite_rate": self.limite_rate.get()
            }
            
            config_dir = os.path.join(os.path.expanduser("~"), ".hashverify")
            os.makedirs(config_dir, exist_ok=True)
            
            with open(os.path.join(config_dir, "config.json"), "w") as f:
                json.dump(config, f)
                
            messagebox.showinfo("Configuração", "Configurações salvas com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar configurações: {str(e)}")
            
    def carregar_config(self):
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".hashverify", "config.json")
            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    config = json.load(f)
                    
                self.api_key.set(config.get("api_key", ""))
                self.limite_rate.set(config.get("limite_rate", 4))
                
                # Se tiver API key, ativar a opção de usar API
                if self.api_key.get():
                    self.usar_api.set(True)
        except Exception:
            # Se falhar ao carregar, apenas continua com os valores padrão
            pass
            
    def testar_api(self):
        api_key = self.api_key.get()
        if not api_key:
            messagebox.showerror("Erro", "API Key não definida")
            return
            
        self.status.set("Testando API VirusTotal...")
        
        # Usar uma thread para não bloquear a interface
        threading.Thread(target=self._testar_api, daemon=True).start()
        
    def _testar_api(self):
        api_key = self.api_key.get()
        
        try:
            # Teste de solicitação simples
            url = "https://www.virustotal.com/api/v3/users/current"
            headers = {
                "x-apikey": api_key
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                # Buscar informações do plano/quota
                data = response.json()
                quota_info = ""
                
                if "data" in data and "attributes" in data["data"]:
                    attrs = data["data"]["attributes"]
                    if "quotas" in attrs:
                        quotas = attrs["quotas"]
                        if "api_requests_daily" in quotas:
                            daily = quotas["api_requests_daily"]
                            if "allowed" in daily and "used" in daily:
                                allowed = daily["allowed"]
                                used = daily["used"]
                                remaining = allowed - used
                                quota_info = f"\n\nQuotas: {used}/{allowed} usadas hoje ({remaining} restantes)"
                
                self.root.after(0, lambda: messagebox.showinfo("Sucesso", f"API VirusTotal conectada com sucesso!{quota_info}"))
                self.root.after(0, lambda: self.status.set("API VirusTotal: Conectada"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Erro ao conectar com a API: {response.status_code}\n{response.text}"))
                self.root.after(0, lambda: self.status.set("API VirusTotal: Erro de conexão"))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Erro ao testar a API: {str(e)}"))
            self.root.after(0, lambda: self.status.set("API VirusTotal: Erro"))
            
    def verificar_hash_virustotal(self, hash_valor, item_id):
        # Verificar se o hash já está no cache
        if hash_valor in self.cache_resultados:
            resultado = self.cache_resultados[hash_valor]
            self.atualizar_resultado_api(item_id, resultado)
            return
            
        # Controle de taxa de solicitações
        espera_necessaria = self._esperar_limite_taxa()
        if espera_necessaria > 0:
            # Atualizar o status para mostrar que estamos esperando
            self.root.after(0, lambda: self.result_table.item(item_id, values=self.result_table.item(item_id, "values")[:3] + (f"Aguardando {espera_necessaria}s",)))
            time.sleep(espera_necessaria)
            
        api_key = self.api_key.get()
        if not api_key:
            self.root.after(0, lambda: self.result_table.item(item_id, values=self.result_table.item(item_id, "values")[:3] + ("Sem API Key",)))
            return
            
        try:
            # Atualizar o status para "Consultando"
            self.root.after(0, lambda: self.result_table.item(item_id, values=self.result_table.item(item_id, "values")[:3] + ("Consultando...",)))
            
            # Realizar a consulta à API
            url = f"https://www.virustotal.com/api/v3/files/{hash_valor}"
            headers = {"x-apikey": api_key}
            
            response = requests.get(url, headers=headers)
            self.tempo_ultima_req = time.time()
            
            if response.status_code == 200:
                data = response.json()
                resultado = self._processar_resposta_vt(data)
                
                # Guardar no cache
                self.cache_resultados[hash_valor] = resultado
                
                # Atualizar a linha na tabela
                self.atualizar_resultado_api(item_id, resultado)
            elif response.status_code == 404:
                # Arquivo não encontrado no VirusTotal
                self.root.after(0, lambda: self.result_table.item(item_id, values=self.result_table.item(item_id, "values")[:3] + ("Não encontrado",)))
            else:
                # Outro erro
                self.root.after(0, lambda: self.result_table.item(item_id, values=self.result_table.item(item_id, "values")[:3] + (f"Erro: {response.status_code}",)))
                
        except Exception as e:
            self.root.after(0, lambda: self.result_table.item(item_id, values=self.result_table.item(item_id, "values")[:3] + (f"Erro: {str(e)}",)))
            
    def _processar_resposta_vt(self, data):
        try:
            if "data" in data and "attributes" in data["data"]:
                attrs = data["data"]["attributes"]
                
                # Análise de detecções
                if "last_analysis_stats" in attrs:
                    stats = attrs["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    
                    # Verificar se é considerado malicioso
                    if malicious > 0:
                        resultado = f"⚠️ {malicious}/{total}"
                        cor = "red"
                    elif suspicious > 0:
                        resultado = f"⚠️ {suspicious}/{total}"
                        cor = "orange"
                    else:
                        resultado = f"✅ 0/{total}"
                        cor = "green"
                        
                    # Pegar nomes populares, se disponíveis
                    nome = ""
                    if "meaningful_name" in attrs:
                        nome = attrs["meaningful_name"]
                    elif "names" in attrs and attrs["names"]:
                        nome = attrs["names"][0]
                        
                    return {
                        "resultado": resultado,
                        "cor": cor,
                        "nome": nome,
                        "detalhes": {
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "total": total
                        }
                    }
                    
            # Se não conseguir processar os dados principais
            return {"resultado": "Formato desconhecido", "cor": None, "nome": "", "detalhes": {}}
            
        except Exception as e:
            return {"resultado": f"Erro: {str(e)}", "cor": None, "nome": "", "detalhes": {}}
            
    def atualizar_resultado_api(self, item_id, resultado):
        valores = self.result_table.item(item_id, "values")
        
        # Atualizar o resultado na tabela
        self.root.after(0, lambda: self.result_table.item(item_id, values=valores[:3] + (resultado["resultado"],)))
        
        # Atualizar a cor com base na detecção
        if resultado["cor"]:
            self.root.after(0, lambda: self.result_table.tag_configure(resultado["cor"], foreground=resultado["cor"]))
            self.root.after(0, lambda: self.result_table.item(item_id, tags=(resultado["cor"],)))
            
    def _esperar_limite_taxa(self):
        """Controle de taxa para respeitar os limites da API"""
        if self.tempo_ultima_req == 0:
            return 0
            
        # Calcular quanto tempo precisa esperar
        tempo_decorrido = time.time() - self.tempo_ultima_req
        intervalo_minimo = 60 / self.limite_rate.get()  # segundos por requisição
        
        if tempo_decorrido < intervalo_minimo:
            # Retorna quanto tempo precisa esperar em segundos
            return int(intervalo_minimo - tempo_decorrido) + 1
        return 0
    
    def mostrar_menu_contexto(self, event):
        # Exibir menu de contexto apenas se houver um item selecionado
        item = self.result_table.identify_row(event.y)
        if item:
            self.result_table.selection_set(item)
            self.menu_contexto.post(event.x_root, event.y_root)
    
    def copiar_hash(self):
        item_selecionado = self.result_table.selection()
        if item_selecionado:
            hash_valor = self.result_table.item(item_selecionado, "values")[2]
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_valor)
            self.status.set("Hash copiado para a área de transferência")
    
    def abrir_link_virustotal(self, event=None):
        if event:  # Se for chamado pelo duplo clique
            item = self.result_table.identify_row(event.y)
            if item:
                self.result_table.selection_set(item)
            else:
                return
        
        item_selecionado = self.result_table.selection()
        if item_selecionado:
            valores = self.result_table.item(item_selecionado, "values")
            hash_valor = valores[2]
            
            # Verificar se é um erro
            if hash_valor.startswith("Erro:"):
                messagebox.showerror("Erro", f"Não é possível verificar este arquivo:\n{hash_valor}")
                return
            
            algoritmo = self.algoritmo.get()
            link = self.gerar_link_virustotal(hash_valor, algoritmo)
            webbrowser.open(link)
            self.status.set(f"Abrindo {valores[0]} no VirusTotal")
            
    def mostrar_detalhes_vt(self):
        """Mostra uma janela com detalhes completos do VirusTotal"""
        item_selecionado = self.result_table.selection()
        if not item_selecionado:
            return
            
        valores = self.result_table.item(item_selecionado, "values")
        hash_valor = valores[2]
        
        # Verificar se é um erro ou se não estamos usando a API
        if hash_valor.startswith("Erro:") or not self.usar_api.get():
            return
            
        # Verificar se o hash está no cache
        if hash_valor not in self.cache_resultados:
            return
            
        resultado = self.cache_resultados[hash_valor]
        detalhes = resultado.get("detalhes", {})
        
        # Criar janela de detalhes
        detalhes_window = tk.Toplevel(self.root)
        detalhes_window.title("Detalhes VirusTotal")
        detalhes_window.geometry("400x300")
        detalhes_window.minsize(400, 300)
        
        # Frame principal
        main_frame = ttk.Frame(detalhes_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Informações do arquivo
        info_frame = ttk.LabelFrame(main_frame, text="Informações do Arquivo", padding=10)
        info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(info_frame, text=f"Nome: {valores[0]}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Caminho: {valores[1]}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Hash: {hash_valor}").pack(anchor=tk.W)
        
        if resultado.get("nome"):
            ttk.Label(info_frame, text=f"Nome detectado: {resultado['nome']}").pack(anchor=tk.W)
        
        # Detalhes de detecção
        if detalhes:
            stats_frame = ttk.LabelFrame(main_frame, text="Estatísticas de Detecção", padding=10)
            stats_frame.pack(fill=tk.X, pady=5)
            
            malicious = detalhes.get("malicious", 0)
            suspicious = detalhes.get("suspicious", 0)
            total = detalhes.get("total", 0)
            
            # Criar uma barra visual
            if total > 0:
                bar_frame = ttk.Frame(stats_frame)
                bar_frame.pack(fill=tk.X, pady=5)
                
                # Criar barras coloridas para representar as detecções
                bar_width = 380  # Largura total da barra
                
                # Calcular proporções
                mal_width = int((malicious / total) * bar_width) if malicious > 0 else 0
                sus_width = int((suspicious / total) * bar_width) if suspicious > 0 else 0
                clean_width = bar_width - mal_width - sus_width
                
                # Criar canvas para desenhar a barra
                canvas = tk.Canvas(bar_frame, width=bar_width, height=20)
                canvas.pack(fill=tk.X)
                
                # Desenhar as barras
                if clean_width > 0:
                    canvas.create_rectangle(0, 0, clean_width, 20, fill="green", outline="")
                if sus_width > 0:
                    canvas.create_rectangle(clean_width, 0, clean_width + sus_width, 20, fill="orange", outline="")
                if mal_width > 0:
                    canvas.create_rectangle(clean_width + sus_width, 0, bar_width, 20, fill="red", outline="")
                
                # Adicionar labels
                ttk.Label(stats_frame, text=f"Maliciosos: {malicious} ({(malicious/total*100):.1f}%)").pack(anchor=tk.W)
                ttk.Label(stats_frame, text=f"Suspeitos: {suspicious} ({(suspicious/total*100):.1f}%)").pack(anchor=tk.W)
                ttk.Label(stats_frame, text=f"Limpo: {total - malicious - suspicious} ({((total - malicious - suspicious)/total*100):.1f}%)").pack(anchor=tk.W)
                ttk.Label(stats_frame, text=f"Total de engines: {total}").pack(anchor=tk.W)
        
        # Botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Abrir no VirusTotal", 
                  command=lambda: webbrowser.open(self.gerar_link_virustotal(hash_valor))).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", 
                  command=detalhes_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def abrir_localizacao(self):
        item_selecionado = self.result_table.selection()
        if item_selecionado:
            caminho = self.result_table.item(item_selecionado, "values")[1]
            diretorio = os.path.dirname(caminho)
            
            # Abrir o Explorer no Windows ou o equivalente em outros sistemas
            if os.path.exists(diretorio):
                if os.name == 'nt':  # Windows
                    os.startfile(diretorio)
                elif os.name == 'posix':  # macOS e Linux
                    try:
                        # Tentar primeiro com xdg-open (Linux)
                        os.system(f'xdg-open "{diretorio}"')
                    except:
                        try:
                            # Tentar com open (macOS)
                            os.system(f'open "{diretorio}"')
                        except:
                            messagebox.showerror("Erro", "Não foi possível abrir o diretório")
            else:
                messagebox.showerror("Erro", "Diretório não encontrado")
                
    def verificar_selecionados_vt(self):
        """Verifica manualmente os itens selecionados usando a API do VirusTotal"""
        itens_selecionados = self.result_table.selection()
        if not itens_selecionados:
            messagebox.showinfo("Aviso", "Nenhum item selecionado")
            return
            
        if not self.usar_api.get():
            resposta = messagebox.askyesno("API não ativada", 
                                         "A API do VirusTotal não está ativada. Deseja ativá-la agora?")
            if resposta:
                self.usar_api.set(True)
                self.toggle_api_config()
            else:
                return
                
        if not self.api_key.get():
            messagebox.showerror("Erro", "API Key não definida")
            return
            
        # Iniciar verificação para cada item selecionado
        for item in itens_selecionados:
            valores = self.result_table.item(item, "values")
            hash_valor = valores[2]
            
            # Pular se for um erro
            if hash_valor.startswith("Erro:"):
                continue
                
            # Atualizar para "Pendente" e iniciar a verificação
            self.result_table.item(item, values=valores[:3] + ("Pendente",))
            threading.Thread(target=self.verificar_hash_virustotal, 
                           args=(hash_valor, item),
                           daemon=True).start()
            
    def submeter_arquivo_vt(self):
        """Submete o arquivo selecionado para análise no VirusTotal"""
        item_selecionado = self.result_table.selection()
        if not item_selecionado:
            messagebox.showinfo("Aviso", "Nenhum item selecionado")
            return
            
        if not self.usar_api.get() or not self.api_key.get():
            messagebox.showerror("Erro", "API Key não definida ou API não ativada")
            return
            
        valores = self.result_table.item(item_selecionado[0], "values")
        caminho = valores[1]
        
        # Verificar se o arquivo existe
        if not os.path.exists(caminho):
            messagebox.showerror("Erro", "Arquivo não encontrado")
            return
            
        # Confirmar o upload
        confirmar = messagebox.askokcancel("Confirmar Upload", 
                                         f"Deseja enviar o arquivo '{valores[0]}' para o VirusTotal?\n\n" +
                                         "Nota: O arquivo será enviado para os servidores do VirusTotal e " +
                                         "ficará disponível publicamente.")
        if not confirmar:
            return
            
        # Atualizar status
        self.result_table.item(item_selecionado[0], values=valores[:3] + ("Enviando...",))
        
        # Função para realizar o upload em thread separada
        def realizar_upload():
            try:
                api_key = self.api_key.get()
                
                # Esperar o limite de taxa se necessário
                espera = self._esperar_limite_taxa()
                if espera > 0:
                    time.sleep(espera)
                
                # Verificar o tamanho do arquivo
                tamanho = os.path.getsize(caminho)
                if tamanho > 32 * 1024 * 1024:  # Limite de 32MB para upload direto
                    self.root.after(0, lambda: messagebox.showerror("Erro", 
                                                                 "Arquivo muito grande para upload direto (>32MB)"))
                    self.root.after(0, lambda: self.result_table.item(
                        item_selecionado[0], values=valores[:3] + ("Muito grande",)))
                    return
                
                # Preparar o upload
                url = "https://www.virustotal.com/api/v3/files"
                files = {"file": (os.path.basename(caminho), open(caminho, "rb"))}
                headers = {"x-apikey": api_key}
                
                # Realizar o upload
                response = requests.post(url, files=files, headers=headers)
                self.tempo_ultima_req = time.time()
                
                if response.status_code == 200:
                    data = response.json()
                    analysis_id = data.get("data", {}).get("id", "")
                    
                    # Atualizar a interface
                    self.root.after(0, lambda: self.result_table.item(
                        item_selecionado[0], values=valores[:3] + ("Análise em andamento",)))
                    
                    # Opcional: Aguardar e obter resultados da análise
                    # Isso pode demorar, então você pode querer implementar uma forma de 
                    # verificar os resultados depois
                    time.sleep(5)  # Dar um tempo para a análise iniciar
                    
                    # Verificar novamente o hash após o upload
                    hash_valor = valores[2]
                    threading.Thread(target=self.verificar_hash_virustotal, 
                                   args=(hash_valor, item_selecionado[0]),
                                   daemon=True).start()
                    
                else:
                    erro = f"Erro {response.status_code}: {response.text}"
                    self.root.after(0, lambda: messagebox.showerror("Erro de Upload", erro))
                    self.root.after(0, lambda: self.result_table.item(
                        item_selecionado[0], values=valores[:3] + (f"Erro: {response.status_code}",)))
                    
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Erro ao enviar arquivo: {str(e)}"))
                self.root.after(0, lambda: self.result_table.item(
                    item_selecionado[0], values=valores[:3] + (f"Erro: {str(e)}",)))
                
        # Iniciar o upload em uma thread separada
        threading.Thread(target=realizar_upload, daemon=True).start()

def main():
    root = tk.Tk()
    app = HashVerifyApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
