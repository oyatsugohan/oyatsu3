import streamlit as st
from datetime import datetime 
# ページ設定
st.set_page_config(
    page_title="詐欺検知アプリ",
    page_icon="🛡️",
    layout="wide"
)
 
# セッション状態の初期化
if 'threat_database' not in st.session_state:
    st.session_state.threat_database = {
        "dangerous_domains": [
            "paypal-secure-login.com",
            "amazon-verify.net",
            "apple-support-id.com",
            "microsoft-security.net",
            "google-verify-account.com"
        ],
        "suspicious_keywords": [
            "verify account", "urgent action", "suspended",
            "confirm identity", "アカウント確認", "緊急",
            "本人確認", "パスワード更新", "セキュリティ警告"
        ],
        "dangerous_patterns": [
            r"http://[^/]*\.(tk|ml|ga|cf|gq)",
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
            r"https?://[^/]*-[^/]*(login|signin|verify)",
        ]
    }
 
if 'reported_sites' not in st.session_state:
    st.session_state.reported_sites = []
 
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
 
# カスタムCSS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .risk-high {
        background-color: #fee2e2;
        border-left: 5px solid #dc2626;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .risk-medium {
        background-color: #fef3c7;
        border-left: 5px solid #f59e0b;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .risk-low {
        background-color: #d1fae5;
        border-left: 5px solid #10b981;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .threat-item {
        background-color: #f9fafb;
        padding: 0.5rem;
        margin: 0.3rem 0;
        border-radius: 3px;
        border-left: 3px solid #6366f1;
    }
</style>
""", unsafe_allow_html=True)
 
# ヘッダー
st.markdown("""
<div class="main-header">
    <h1>🛡️ フィッシング詐欺検知アプリ</h1>
    <p>AIと脅威データベースで怪しいURLやメールを分析</p>
</div>
""", unsafe_allow_html=True)
 
# サイドバー
with st.sidebar:
    st.header("⚙️ 設定")
    api_key = st.text_input(
        "Gemini APIキー（オプション）",
        type="password",
        help="AI分析を使用する場合は入力してください: https://makersuite.google.com/app/apikey"
    )
   
    st.markdown("---")
   
    st.markdown("""
    ### 📝 機能
    - **URLチェック**: URL安全性分析
    - **メールチェック**: メール内容分析
    - **ローカル分析**: データベースベース
    - **AI分析**: Gemini活用（要APIキー）
    - **通報機能**: 怪しいサイト共有
    - **脅威情報**: 最新データベース
   
    ### ⚠️ 注意
    - APIキーは安全に管理
    - 個人情報は入力禁止
    - 最終判断は慎重に
    """)
st.title('インターネット詐欺対策アプリ')
st.write('こちらはインターネット詐欺対策アプリです。ご用件をうかがってもよいでしょうか。')
if st.button('詐欺かどうか調べてほしい') or st.button('詐欺の見極め方を教えてほしい'):
    st.write('了解しました。少しお待ちください。')
else:
    st.write('ご用件をお願いします。')