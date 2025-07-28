import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime

def carregar_logs(caminho_csv):
    df = pd.read_csv(caminho_csv)
    print(f"[INFO] {len(df)} registros carregados.")
    return df

def detectar_anomalias(df, colunas_analise):
    modelo = IsolationForest(contamination=0.05, random_state=42)
    df['anomalia'] = modelo.fit_predict(df[colunas_analise])
    df['score'] = modelo.decision_function(df[colunas_analise])
    return df

def classificar_risco(score):
    if score < -0.25:
        return "ALTO"
    elif score < -0.10:
        return "MÉDIO"
    else:
        return "BAIXO"

def gerar_relatorio(df_anomalias):
    data = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    caminho = f"relatorio_seguranca_{data}.txt"
    
    with open(caminho, 'w', encoding='utf-8') as f:
        f.write(f"🛡️ Relatório de Segurança - {data}\n\n")
        for _, row in df_anomalias.iterrows():
            f.write(f"📅 Data/Hora: {row['timestamp']}\n")
            f.write(f"🌐 IP: {row['ip']}\n")
            f.write(f"🔐 Ação: {row['acao']}\n")
            f.write(f"⚠️ Score de Anomalia: {row['score']:.4f}\n")
            risco = classificar_risco(row['score'])
            f.write(f"⚠️ Risco: {risco}\n")
            f.write("-" * 40 + "\n")
    
    print(f"[INFO] Relatório gerado: {caminho}")

# Execução principal
if __name__ == "__main__":
    logs = carregar_logs("logs.csv")  # você pode gerar um CSV simulado
    colunas_para_analisar = ["porta_origem", "porta_destino", "tamanho_pacote"]
    resultado = detectar_anomalias(logs, colunas_para_analisar)
    anomalias = resultado[resultado['anomalia'] == -1]
    
    print(f"[INFO] {len(anomalias)} possíveis ameaças detectadas.")
    gerar_relatorio(anomalias)
