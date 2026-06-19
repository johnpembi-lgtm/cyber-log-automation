import pandas as pd
import streamlit as st
import plotly.express as px

st.title("Cyber Log Automation Dashboard")

df = pd.read_csv("reports/alertes.csv")

st.dataframe(df)

fig = px.bar(
df,
x="IP",
y="Nombre Alertes",
title="Alertes par IP"
)

st.plotly_chart(fig)

top_ip = df.loc[df["Nombre Alertes"].idxmax()]

st.metric(
"IP la plus suspecte",
top_ip["IP"],
top_ip["Nombre Alertes"]
)
