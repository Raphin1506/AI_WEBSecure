import threading
import queue
import csv
import time
from collections import defaultdict, deque
from scapy.all import sniff, wrpcap
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from tkinter import filedialog, messagebox
from datetime import datetime  # <-- NOVO

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Monitor")
        self.running = False
        self.packet_queue = queue.Queue()
        self.packets = []
        self.theme = tb.StringVar(value="superhero")

        # Controle de sessão / estatísticas  <-- NOVO
        self.session_start = None
        self.session_end = None
        self.stats = {
            'total': 0,
            'suspicious': 0,
            'reasons': defaultdict(int),
            'syn_by_ip': defaultdict(int),
            'ports': defaultdict(int),
            'alerts': []
        }

        # Top Frame: Tema e botões de salvar/exportar
        topfrm = tb.Frame(root, padding=6)
        topfrm.pack(fill=X)
        tb.Label(topfrm, text="Tema:").pack(side=LEFT)
        theme_combo = tb.Combobox(
            topfrm, textvariable=self.theme,
            values=["superhero", "flatly", "darkly", "journal", "minty", "pulse", "solar", "united", "morph", "litera", "cosmo"],
            width=10, state="readonly"
        )
        theme_combo.pack(side=LEFT, padx=5)
        theme_combo.bind("<<ComboboxSelected>>", self.change_theme)
        tb.Button(topfrm, text="Salvar .pcap", bootstyle=SECONDARY, command=self.save_pcap).pack(side=LEFT, padx=10)
        tb.Button(topfrm, text="Exportar CSV", bootstyle=INFO, command=self.export_csv).pack(side=LEFT)
        # Botão de relatório  <-- NOVO
        self.report_btn = tb.Button(topfrm, text="Gerar Relatório", bootstyle=PRIMARY,
                                    command=self.generate_report, state=DISABLED)
        self.report_btn.pack(side=LEFT, padx=10)

        # Frame de interface e filtro
        frm = tb.Frame(root, padding=8)
        frm.pack(fill=X)
        tb.Label(frm, text="Interface:").pack(side=LEFT)
        self.iface_entry = tb.Entry(frm, width=18)
        self.iface_entry.pack(side=LEFT)
        self.iface_entry.insert(0, "Ethernet")
        tb.Label(frm, text="Filtro (ex: tcp port 80, udp, icmp, host 8.8.8.8):").pack(side=LEFT, padx=(10, 5))
        self.filter_entry = tb.Entry(frm, width=32)
        self.filter_entry.pack(side=LEFT)
        self.filter_entry.insert(0, "")
        self.start_btn = tb.Button(frm, text="Iniciar", bootstyle=SUCCESS, command=self.start_sniffing)
        self.start_btn.pack(side=LEFT, padx=8)
        self.stop_btn = tb.Button(frm, text="Parar", bootstyle=DANGER, command=self.stop_sniffing, state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=8)

        # Dica do filtro BPF/Wireshark
        tipfrm = tb.Frame(root)
        tipfrm.pack(fill=X)
        tb.Label(tipfrm, text="Exemplos de filtro: ", bootstyle=SECONDARY).pack(side=LEFT)
        tb.Label(tipfrm, text='icmp  |  tcp port 80  |  udp  |  host 8.8.8.8  |  port 53  |  src net 192.168.1.0/24', bootstyle=INFO).pack(side=LEFT)

        # Área de alertas automáticos
        self.alert_area = ScrolledText(root, height=4, autohide=True, bootstyle=WARNING)
        self.alert_area.pack(fill=BOTH, expand=False, padx=10, pady=(0,5))

        # Lista de pacotes suspeitos
        self.tree = tb.Treeview(root, columns=('Resumo',), show='headings', height=13, bootstyle=INFO)
        self.tree.heading('Resumo', text='Resumo do Pacote Suspeito')
        self.tree.pack(fill=BOTH, expand=True, padx=10, pady=(0,5))
        self.tree.bind('<Double-1>', self.show_packet_details)

        # Detalhes do pacote
        self.details = ScrolledText(root, height=8, autohide=True, bootstyle=SECONDARY)
        self.details.pack(fill=BOTH, expand=True, padx=10, pady=(0,10))

        # Estatísticas para heurística de atividades suspeitas
        self.icmp_times = deque(maxlen=50)
        self.syn_counts = defaultdict(int)
        self.last_alert = 0

        self.root.after(100, self.update_packets)

    def start_sniffing(self):
        self.running = True
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.report_btn.config(state=DISABLED)  # <-- NOVO
        self.tree.delete(*self.tree.get_children())
        self.packets.clear()
        self.icmp_times.clear()
        self.syn_counts.clear()

        # Reset sessão/estatísticas  <-- NOVO
        self.session_start = time.time()
        self.session_end = None
        self.stats = {
            'total': 0,
            'suspicious': 0,
            'reasons': defaultdict(int),
            'syn_by_ip': defaultdict(int),
            'ports': defaultdict(int),
            'alerts': []
        }

        iface = self.iface_entry.get()
        bpf = self.filter_entry.get()
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(iface, bpf), daemon=True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.running = False
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.session_end = time.time()  # <-- NOVO
        if self.stats['total'] > 0:
            self.report_btn.config(state=NORMAL)  # habilita relatório quando há dados

    def sniff_packets(self, iface, bpf):
        def pkt_callback(pkt):
            self.packet_queue.put(pkt)
        try:
            sniff(iface=iface, filter=bpf, prn=pkt_callback, stop_filter=lambda _: not self.running, store=0)
        except Exception as e:
            self.packet_queue.put(f"ERRO: {str(e)}")
            self.running = False

    def update_packets(self):
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()
            if isinstance(pkt, str) and pkt.startswith("ERRO"):
                self.details.insert('end', pkt + "\n")
                self.details.see('end')
            else:
                # contabiliza total  <-- NOVO
                self.stats['total'] += 1

                suspicious, reason = self.is_suspicious_packet(pkt)
                self.check_suspicious(pkt)  # mantém a heurística de alerta

                if suspicious:
                    idx = len(self.packets)
                    self.packets.append(pkt)
                    display_summary = pkt.summary() + (f"  [{reason}]" if reason else "")
                    self.tree.insert('', 'end', iid=str(idx), values=(display_summary,))

                    # contabiliza suspeitos/motivos/auxiliares  <-- NOVO
                    self.stats['suspicious'] += 1
                    if reason:
                        self.stats['reasons'][reason] += 1
                        if reason.startswith("SYN flood do IP"):
                            # extrai IP
                            ip = reason.split()[-1]
                            self.stats['syn_by_ip'][ip] = self.syn_counts.get(ip, self.stats['syn_by_ip'].get(ip, 0))
                        if reason.startswith("Porta incomum"):
                            try:
                                p = int(reason.split()[-1])
                                self.stats['ports'][p] += 1
                            except Exception:
                                pass

        self.root.after(100, self.update_packets)

    def is_suspicious_packet(self, pkt):
        now = time.time()
        # ICMP flood (acumula tempos)
        if pkt.haslayer("ICMP"):
            self.icmp_times.append(now)
            recent_icmp = [t for t in self.icmp_times if now - t < 3]
            if len(recent_icmp) > 10:
                return True, "ICMP flood"
        # SYN flood (acumula SYN por IP)
        if pkt.haslayer("TCP") and pkt["TCP"].flags == "S":
            src = pkt["IP"].src if pkt.haslayer("IP") else "?"
            self.syn_counts[src] += 1
            if self.syn_counts[src] > 20:
                return True, f"SYN flood do IP {src}"
        # Portas incomuns
        if pkt.haslayer("TCP"):
            port = pkt["TCP"].dport
            if port in [23, 3389, 445, 1433]:
                return True, f"Porta incomum {port}"
        return False, ""

    def show_packet_details(self, event):
        item = self.tree.selection()
        if not item:
            return
        idx = int(item[0])
        pkt = self.packets[idx]
        self.details.delete('1.0', 'end')
        self.details.insert('end', pkt.show(dump=True))
        self.details.see('end')

    def save_pcap(self):
        if not self.packets:
            messagebox.showinfo("Aviso", "Nenhum pacote para salvar!")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if filepath:
            wrpcap(filepath, self.packets)
            messagebox.showinfo("Sucesso", f"Pacotes salvos em {filepath}")

    def export_csv(self):
        if not self.packets:
            messagebox.showinfo("Aviso", "Nenhum pacote para exportar!")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filepath:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Resumo", "Camadas"])
                for pkt in self.packets:
                    summary = pkt.summary()
                    layers = ", ".join(layer.__class__.__name__ for layer in pkt.layers())
                    writer.writerow([summary, layers])
            messagebox.showinfo("Sucesso", f"Pacotes exportados para {filepath}")

    def change_theme(self, *args):
        new_theme = self.theme.get()
        self.root.style.theme_use(new_theme)

    def check_suspicious(self, pkt):
        now = time.time()
        # Mantém os alertas em tempo real
        if pkt.haslayer("ICMP"):
            self.icmp_times.append(now)
            recent_icmp = [t for t in self.icmp_times if now - t < 3]
            if len(recent_icmp) > 10 and (now - self.last_alert > 3):
                self.raise_alert("Possível ICMP flood detectado!")
        if pkt.haslayer("TCP") and pkt["TCP"].flags == "S":
            src = pkt["IP"].src if pkt.haslayer("IP") else "?"
            self.syn_counts[src] += 1
            if self.syn_counts[src] > 20 and (now - self.last_alert > 3):
                self.raise_alert(f"Possível SYN flood do IP {src}!")
        if pkt.haslayer("TCP"):
            port = pkt["TCP"].dport
            if port in [23, 3389, 445, 1433]:
                self.raise_alert(f"Tráfego para porta suspeita detectado: {port}")

    def raise_alert(self, msg):
        self.alert_area.insert('end', f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.alert_area.see('end')
        self.last_alert = time.time()
        # guarda alerta para o relatório  <-- NOVO
        self.stats['alerts'].append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

    # --------- NOVO: Geração de relatório HTML ----------
    def generate_report(self):
        if self.stats['total'] == 0:
            messagebox.showinfo("Aviso", "Nenhum dado para relatar!")
            return

        start_dt = datetime.fromtimestamp(self.session_start) if self.session_start else None
        end_dt = datetime.fromtimestamp(self.session_end) if self.session_end else datetime.now()
        duration = (end_dt - start_dt).total_seconds() if start_dt else 0

        iface = self.iface_entry.get()
        bpf = self.filter_entry.get()

        def html_table_from_kv(title, mapping):
            rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in mapping.items())
            return f"<h3>{title}</h3><table border='1' cellspacing='0' cellpadding='6'><tr><th>Chave</th><th>Valor</th></tr>{rows}</table>"

        # Motivos agregados
        reasons = dict(sorted(self.stats['reasons'].items(), key=lambda x: x[1], reverse=True))
        syn_by_ip = dict(sorted(self.stats['syn_by_ip'].items(), key=lambda x: x[1], reverse=True))
        ports = dict(sorted(self.stats['ports'].items(), key=lambda x: x[1], reverse=True))

        suspicious_list_items = ""
        for i, pkt in enumerate(self.packets):
            suspicious_list_items += f"<li><code>{pkt.summary()}</code></li>"

        alerts_html = "".join(f"<li>{a}</li>" for a in self.stats['alerts'])

        html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>Relatório - Packet Monitor</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; }}
h1, h2, h3 {{ margin-bottom: 8px; }}
section {{ margin-bottom: 20px; }}
table {{ border-collapse: collapse; width: 100%; max-width: 900px; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
small {{ color: #666; }}
</style>
</head>
<body>
<h1>Relatório de Varredura</h1>
<section>
  <p><b>Início:</b> {start_dt.strftime('%Y-%m-%d %H:%M:%S') if start_dt else '-'}<br>
     <b>Fim:</b> {end_dt.strftime('%Y-%m-%d %H:%M:%S')}<br>
     <b>Duração:</b> {int(duration)}s<br>
     <b>Interface:</b> {iface}<br>
     <b>Filtro:</b> {bpf if bpf else '(nenhum)'}
  </p>
</section>

<section>
  <h2>Resumo</h2>
  <table>
    <tr><th>Total de pacotes processados</th><td>{self.stats['total']}</td></tr>
    <tr><th>Pacotes considerados suspeitos</th><td>{self.stats['suspicious']}</td></tr>
  </table>
</section>

<section>
  {html_table_from_kv("Motivos de suspeita (agregado)", reasons if reasons else {"(vazio)": 0})}
</section>

<section>
  {html_table_from_kv("SYN por IP (contagem de SYN observados)", syn_by_ip if syn_by_ip else {"(vazio)": 0})}
</section>

<section>
  {html_table_from_kv("Portas suspeitas acessadas", ports if ports else {"(vazio)": 0})}
</section>

<section>
  <h2>Alertas durante a sessão</h2>
  <ul>
    {alerts_html if alerts_html else "<li>(nenhum)</li>"}
  </ul>
</section>

<section>
  <h2>Pacotes suspeitos (resumo)</h2>
  <ol>
    {suspicious_list_items if suspicious_list_items else "<li>(nenhum)</li>"}
  </ol>
  <small>Dica: use o botão “Salvar .pcap” para analisar estes pacotes no Wireshark.</small>
</section>

<hr>
<small>Gerado por Packet Monitor em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
</body>
</html>
"""

        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML", "*.html")],
            title="Salvar relatório"
        )
        if not filepath:
            return
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            messagebox.showinfo("Sucesso", f"Relatório salvo em {filepath}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar relatório: {e}")

if __name__ == '__main__':
    app = tb.Window(themename="superhero")
    PacketSnifferGUI(app)
    app.mainloop()
