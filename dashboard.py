import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime

# Dicionário de recomendações
RECOMENDACOES = {
    "SSH": "Verificar tentativas de brute force e bloquear IP se necessário.",
    "RDP": "Avaliar necessidade de acesso remoto e aplicar autenticação forte.",
    "FTP": "Desabilitar FTP se não for necessário; usar SFTP como alternativa segura.",
    "SMB": "Verificar exposição da porta 445 e aplicar patches de segurança.",
    "POST": "Monitorar payloads recebidos — pode indicar tentativa de injeção ou exfiltração.",
    "MySQL": "Verificar acessos não autorizados e revisar credenciais do banco de dados.",
    "GET": "Monitorar volume de requisições para evitar possíveis ataques de scraping ou DDoS."
}

def sugerir_acao(acao):
    return RECOMENDACOES.get(acao, "Investigar atividade incomum e revisar políticas de acesso.")

def detectar_anomalias(df, colunas):
    modelo = IsolationForest(contamination=0.05, random_state=42)
    df['score'] = modelo.fit_predict(df[colunas])
    df['anomalia'] = modelo.decision_function(df[colunas])
    df['risco'] = df['anomalia'].apply(classificar_risco)
    df['acao_recomendada'] = df['acao'].apply(sugerir_acao)
    return df[df['score'] == -1]  # Somente anomalias

def classificar_risco(score):
    if score < -0.25:
        return "ALTO"
    elif score < -0.10:
        return "MÉDIO"
    else:
        return "BAIXO"

def gerar_relatorio_txt(df):
    data = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nome = f"relatorio_seguranca_{data}.txt"
    with open(nome, 'w', encoding='utf-8') as f:
        f.write(f"🛡️ Relatório de Segurança - {data}\n\n")
        for _, row in df.iterrows():
            f.write(f"📅 Data/Hora: {row['timestamp']}\n")
            f.write(f"🌐 IP: {row['ip']}\n")
            f.write(f"🔐 Ação: {row['acao']}\n")
            f.write(f"⚠️ Score de Anomalia: {row['anomalia']:.4f}\n")
            f.write(f"🚨 Risco: {row['risco']}\n")
            f.write(f"💡 Ação Recomendada: {row['acao_recomendada']}\n")
            f.write("-" * 40 + "\n")
    return nome

# Streamlit App
st.set_page_config(page_title="CyberSentinel IA", layout="wide")
st.title("🔍 CyberSentinel AI - Monitoramento de Ameaças")
st.write("Faça upload de um arquivo de log (.csv) para iniciar a análise.")

uploaded_file = st.file_uploader("Upload do arquivo de log:", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success("Arquivo carregado com sucesso!")
    st.write("Prévia dos dados:")
    st.dataframe(df.head())

    colunas_para_analise = ["porta_origem", "porta_destino", "tamanho_pacote"]

    if st.button("🚨 Analisar Ameaças"):
        resultados = detectar_anomalias(df, colunas_para_analise)

        if resultados.empty:
            st.success("Nenhuma anomalia detectada.")
        else:
            st.error(f"{len(resultados)} ameaças detectadas!")
            st.dataframe(resultados[["timestamp", "ip", "acao", "anomalia", "risco", "acao_recomendada"]])

            caminho = gerar_relatorio_txt(resultados)
            with open(caminho, 'rb') as f:
                st.download_button(
                    label="⬇️ Baixar Relatório",
                    data=f,
                    file_name=caminho,
                    mime="text/plain"
                )

