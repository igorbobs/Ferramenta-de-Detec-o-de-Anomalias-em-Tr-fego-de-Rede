import pandas as pd
import subprocess

def pcap_to_csv(pcap_path, csv_path):
    command = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "ip.proto",
        "-e", "frame.len"
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        with open(csv_path, 'w') as f:
            f.write(process.stdout)

        df = pd.read_csv(csv_path)

        # Unificar portas TCP e UDP
        df['src_port'] = df['tcp.srcport'].fillna(df['udp.srcport'])
        df['dst_port'] = df['tcp.dstport'].fillna(df['udp.dstport'])

        # Renomear colunas para nomes mais amigáveis
        df = df.rename(columns={
            'frame.time_epoch': 'timestamp',
            'ip.src': 'src_ip',
            'ip.dst': 'dst_ip',
            'ip.proto': 'protocol',
            'frame.len': 'packet_length'
        })

        # Remover colunas originais de porta TCP/UDP
        df = df.drop(columns=['tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport'])

        # Preencher NaNs em portas com 0 (para pacotes não TCP/UDP)
        df['src_port'] = df['src_port'].fillna(0).astype(int)
        df['dst_port'] = df['dst_port'].fillna(0).astype(int)

        # Salvar o CSV processado
        df.to_csv(csv_path, index=False)

    except FileNotFoundError:
        print("Erro: TShark não encontrado. Certifique-se de que o Wireshark está instalado e o tshark está no PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar TShark: {e}")
        print(f"Erro Stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")
        return False
    return True
