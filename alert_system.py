import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# Carrega variáveis do arquivo .env
load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
ALERT_SCORE_THRESHOLD = float(os.getenv("ALERT_SCORE_THRESHOLD", "-0.19"))


def classify_anomaly(row):
    score = row['anomaly_score']
    if score < ALERT_SCORE_THRESHOLD:
        return "Alto risco: possível ataque grave detectado. Verifique imediatamente."
    elif score < -0.1:
        return "Médio risco: comportamento incomum identificado."
    else:
        return "Baixo risco: monitorar."


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
                       f"Src Port: {row['src_port']}, Dst Port: {row['dst_port']}, Protocolo: {protocol_num_to_name(int(row['protocol']))}\n"
                       f"Tamanho: {row['packet_length']} bytes\n"
                       f"Score: {row['anomaly_score']:.4f}\n"
                       f"Classificação: {classification}\n\n")
    return alert_body
