import streamlit as st

st.title('フィッシング詐欺対策アプリ')
st.write('こちらはフィッシング詐欺対策アプリです。ご用件をうかがってもよいでしょうか。')
if st.button('アプリがフィッシング詐欺かどうか調べてほしい') or st.button('フィッシング詐欺の見極め方を教えてほしい'):
    st.write('了解しました。少しお待ちください。')
else:
    st.write('ご用件をお願いします。')