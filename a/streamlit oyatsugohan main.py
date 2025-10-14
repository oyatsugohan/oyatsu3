import streamlit as st

st.title('インターネット詐欺対策アプリ')
st.write('こちらはインターネット詐欺対策アプリです。ご用件をうかがってもよいでしょうか。')
if st.button('詐欺かどうか調べてほしい') or st.button('詐欺の見極め方を教えてほしい'):
    st.write('了解しました。少しお待ちください。')
else:
    st.write('ご用件をお願いします。')