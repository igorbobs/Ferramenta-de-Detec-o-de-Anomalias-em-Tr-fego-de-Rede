import pandas as pd
import argparse
import os
import re
import datetime
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from pcap_converter import pcap_to_csv
from anomaly_detector import detect_anomalies

# Carregar variáveis do .env
load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
ALERT_SCORE_THRESHOLD = float(os.getenv("ALERT_SCORE_THRESHOLD", "-0.2"))


def classify_anomaly(row):
    score = row['anomaly_score']
    src_port = row['src_port']
    dst_port = row['dst_port']
    src_ip = row['src_ip']
    dst_ip = row['dst_ip']
    packet_length = row['packet_length']

    messages = []

    # Risco base no score
    if score < ALERT_SCORE_THRESHOLD:
        risk = "Alto risco"
    elif score < -0.1:
        risk = "Médio risco"
    else:
        risk = "Baixo risco"

    messages.append(f"Risco: {risk}")

    # Porta fora do comum (exemplo heurístico)
    common_ports = {80, 443, 22, 53, 123}
    if src_port not in common_ports and src_port != 0:
        messages.append(f"Porta origem incomum: {src_port}")
    if dst_port not in common_ports and dst_port != 0:
        messages.append(f"Porta destino incomum: {dst_port}")

    # Tamanho muito atípico
    if packet_length > 1500:
        messages.append(f"Pacote muito grande ({packet_length} bytes)")

    # IP externo suspeito (exemplo simples, considerar rede local 192.168/10.0)
    def is_external(ip):
        return not (ip.startswith("192.168.") or ip.startswith("10."))

    if is_external(src_ip):
        messages.append(f"IP origem externo: {src_ip}")
    if is_external(dst_ip):
        messages.append(f"IP destino externo: {dst_ip}")

    # Sugestão simples
    if risk == "Alto risco":
        messages.append("Sugerido: verificação imediata e isolamento da origem.")
    elif risk == "Médio risco":
        messages.append("Sugerido: revisão detalhada.")

    return " | ".join(messages)


def send_email_alert(subject, body):
    """
    Envia um email usando SMTP SSL com configurações do .env.
    """
    if not all([EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER]):
        print("Configurações de email incompletas no .env")
        return False

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"Erro ao enviar email: {e}")
        return False


def prepare_alert_report(anomalies_df, protocol_num_to_name):
    critical_alerts = anomalies_df[anomalies_df['anomaly_score'] < ALERT_SCORE_THRESHOLD]
    if critical_alerts.empty:
        return None

    alert_body = "ALERTAS DE ALTO RISCO DETECTADOS:\n\n"
    for idx, row in critical_alerts.iterrows():
        classification = classify_anomaly(row)
        alert_body += (f"Timestamp: {row['timestamp']}\n"
                       f"Src IP: {row['src_ip']} -> Dst IP: {row['dst_ip']}\n"
                       f"Src Port: {row['src_port']}, Dst Port: {row['dst_port']}, "
                       f"Protocolo: {protocol_num_to_name(int(row['protocol']))}\n"
                       f"Tamanho: {row['packet_length']} bytes\n"
                       f"Score: {row['anomaly_score']:.4f}\n"
                       f"Classificação: {classification}\n\n")
    return alert_body


def convert_relative_timestamp(base_datetime, relative_seconds):
    return base_datetime + datetime.timedelta(seconds=relative_seconds)


def protocol_num_to_name(proto_num):
    proto_map = {
        6: 'TCP',
        17: 'UDP',
        1: 'ICMP',
        0: 'Desconhecido'
    }
    return proto_map.get(proto_num, f"Outro({proto_num})")


def convert_wireshark_csv(df, console):
    console.print("[bold blue]Formato Wireshark detectado, iniciando conversão para formato interno...[/bold blue]")
    base_datetime = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    df['timestamp'] = df['Time'].astype(float).apply(lambda x: convert_relative_timestamp(base_datetime, x))
    df = df.rename(columns={'Source': 'src_ip', 'Destination': 'dst_ip', 'Protocol': 'protocol', 'Length': 'packet_length'})

    src_ports = []
    dst_ports = []
    port_pattern = re.compile(r"(\d+)\s*>\s*(\d+)")
    for info in df['Info']:
        match = port_pattern.search(info)
        if match:
            src_ports.append(int(match.group(1)))
            dst_ports.append(int(match.group(2)))
        else:
            src_ports.append(0)
            dst_ports.append(0)
    df['src_port'] = src_ports
    df['dst_port'] = dst_ports

    proto_text_to_num = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
    df['protocol'] = df['protocol'].apply(lambda x: proto_text_to_num.get(str(x).upper(), 0))

    console.print("[bold green]Conversão do CSV Wireshark concluída com sucesso![/bold green]")
    df = df[['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length']]
    return df


def main():
    parser = argparse.ArgumentParser(description="Ferramenta de Detecção de Anomalias em Tráfego de Rede.")
    parser.add_argument("input_file", help="Caminho para o arquivo .pcap ou .csv")
    args = parser.parse_args()

    console = Console()
    input_path = args.input_file
    output_csv_path = "data/processed_traffic.csv"
    os.makedirs("data", exist_ok=True)

    df = None

    if input_path.endswith(".pcap"):
        console.print(f"[bold blue]Iniciando conversão de {input_path} para CSV...[/bold blue]")
        if pcap_to_csv(input_path, output_csv_path):
            console.print("[bold green]Conversão concluída com sucesso![/bold green]")
            df = pd.read_csv(output_csv_path)
        else:
            console.print("[bold red]Falha na conversão do arquivo PCAP.[/bold red]")
            return
    elif input_path.endswith(".csv"):
        console.print(f"[bold blue]Carregando dados do CSV: {input_path}...[/bold blue]")
        try:
            df = pd.read_csv(input_path)
            if 'No.' in df.columns and 'Time' in df.columns and 'Source' in df.columns:
                df = convert_wireshark_csv(df, console)
            else:
                expected_cols = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length']
                if not all(col in df.columns for col in expected_cols):
                    console.print("[bold yellow]CSV de entrada não possui todas as colunas esperadas. Tentando pré-processamento...[/bold yellow]")
                    df['src_port'] = df['tcp.srcport'].fillna(df['udp.srcport']) if 'tcp.srcport' in df.columns else 0
                    df['dst_port'] = df['tcp.dstport'].fillna(df['udp.dstport']) if 'tcp.dstport' in df.columns else 0
                    df = df.rename(columns={
                        'frame.time_epoch': 'timestamp',
                        'ip.src': 'src_ip',
                        'ip.dst': 'dst_ip',
                        'ip.proto': 'protocol',
                        'frame.len': 'packet_length'
                    })
                    df = df.drop(columns=[col for col in ['tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport'] if col in df.columns])
                    df['src_port'] = df['src_port'].fillna(0).astype(int)
                    df['dst_port'] = df['dst_port'].fillna(0).astype(int)
                    console.print("[bold green]Pré-processamento do CSV concluído.[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Erro ao carregar ou pré-processar o arquivo CSV: {e}[/bold red]")
            return
    else:
        console.print("[bold red]Formato de arquivo não suportado. Use .pcap ou .csv.[/bold red]")
        return

    if df is None or df.empty:
        console.print("[bold red]Nenhum dado para analisar. Encerrando.[/bold red]")
        return

    console.print("[bold blue]Iniciando detecção de anomalias...[/bold blue]")
    anomalies_df = detect_anomalies(df)
    console.print("[bold green]Detecção de anomalias concluída![/bold green]")

    # Classificar anomalias com detalhamento
    anomalies_df['classification'] = anomalies_df.apply(classify_anomaly, axis=1)

    # Preparar relatório e enviar alerta se necessário
    report = prepare_alert_report(anomalies_df, protocol_num_to_name)

    if report:
        if send_email_alert("Alerta de Anomalias Críticas", report):
            console.print("[bold green]Email de alerta enviado com sucesso.[/bold green]")
        else:
            console.print("[bold red]Falha ao enviar o email de alerta.[/bold red]")

    # --- Apresentação dos Resultados com Rich --- #

    console.print("\n" + "[bold cyan]─" * 60)
    console.print(Panel(
        Text(f"Total de Pacotes Analisados: {len(df)}\nTotal de Anomalias Detectadas: {len(anomalies_df)}", justify="center"),
        title="[bold]Resumo da Análise[/bold]",
        border_style="cyan"
    ))

    if not anomalies_df.empty:
        console.print("\n" + "[bold yellow]─" * 60)
        console.print(Panel(
            Text("Top Anomalias Detectadas (mais anômalas primeiro)", justify="center"),
            title="[bold]Anomalias Detalhadas[/bold]",
            border_style="yellow"
        ))

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Timestamp", style="dim", width=20)
        table.add_column("IP Origem", justify="left")
        table.add_column("IP Destino", justify="left")
        table.add_column("P. Origem", justify="right")
        table.add_column("P. Destino", justify="right")
        table.add_column("Protocolo", justify="center")
        table.add_column("Tam. Pacote", justify="right")
        table.add_column("Score", justify="right", style="red")
        table.add_column("Detalhamento", justify="left")

        top_n_anomalies = anomalies_df.head(10)

        for _, row in top_n_anomalies.iterrows():
            table.add_row(
                str(row['timestamp']),
                str(row['src_ip']),
                str(row['dst_ip']),
                str(row['src_port']),
                str(row['dst_port']),
                protocol_num_to_name(int(row['protocol'])),
                str(row['packet_length']),
                f"{row['anomaly_score']:.4f}",
                row['classification']
            )

        console.print(table)
    else:
        console.print(Panel(
            Text("Nenhuma anomalia detectada neste tráfego.", justify="center"),
            title="[bold]Anomalias Detalhadas[/bold]",
            border_style="green"
        ))

    console.print("[bold cyan]─" * 60 + "\n")


if __name__ == "__main__":
    main()