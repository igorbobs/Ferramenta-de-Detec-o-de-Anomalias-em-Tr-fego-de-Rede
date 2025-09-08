import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def detect_anomalies(df):
    # Copia o DataFrame para evitar SettingWithCopyWarning
    df_processed = df.copy()

    # Criação de features numéricas para IPs
    df_processed['src_ip_code'] = pd.factorize(df_processed['src_ip'])[0]
    df_processed['dst_ip_code'] = pd.factorize(df_processed['dst_ip'])[0]

    # Garante que 'protocol' é numérico (se já não for)
    # Pode ser necessário um mapeamento mais robusto para protocolos se houver muitos
    df_processed['protocol'] = pd.to_numeric(df_processed['protocol'], errors='coerce').fillna(0).astype(int)

    features_for_model = ['src_ip_code', 'dst_ip_code', 'src_port', 'dst_port', 'protocol', 'packet_length']
    X = df_processed[features_for_model].fillna(0) # Garante que não há NaNs

    # Normalização dos dados
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Instanciação e treinamento do modelo
    # contamination='auto' é uma boa opção para começar
    clf = IsolationForest(contamination='auto', random_state=42)
    clf.fit(X_scaled)

    # Predição e obtenção dos scores
    df_processed['anomaly'] = clf.predict(X_scaled)
    df_processed['anomaly_score'] = clf.decision_function(X_scaled)

    # Filtra e ordena as anomalias
    anomalies = df_processed[df_processed['anomaly'] == -1].sort_values(by='anomaly_score')

    return anomalies

