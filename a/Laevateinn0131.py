import streamlit as st
import google as genai
import json
import re
from datetime import datetime
from urllib.parse import urlparse
import time
 
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
 
# メインタブ
tab1, tab2, tab3, tab4 = st.tabs(["🔍 URLチェック", "📧 メールチェック", "📢 通報・共有", "⚠️ 脅威情報"])
 
# URLチェック関数
def analyze_url_local(url):
    """ローカルデータベースでURL解析"""
    results = {
        "url": url,
        "risk_level": "安全",
        "risk_score": 10,
        "warnings": [],
        "details": []
    }
   
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
       
        if not domain:
            results["risk_level"] = "エラー"
            results["risk_score"] = 0
            results["warnings"].append("❌ 有効なURLではありません")
            return results
       
        # 危険ドメインチェック
        if any(d in domain for d in st.session_state.threat_database["dangerous_domains"]):
            results["risk_level"] = "危険"
            results["risk_score"] = 95
            results["warnings"].append("⚠️ 既知の詐欺サイトです！直ちにアクセスを中止してください")
       
        # パターンマッチング
        for pattern in st.session_state.threat_database["dangerous_patterns"]:
            if re.search(pattern, url):
                if results["risk_level"] == "安全":
                    results["risk_level"] = "注意"
                    results["risk_score"] = 60
                results["warnings"].append(f"⚠️ 疑わしいURLパターンを検出")
                break
       
        # HTTPSチェック
        if parsed.scheme == "http":
            results["warnings"].append("⚠️ HTTPSではありません（通信が暗号化されていません）")
            if results["risk_level"] == "安全":
                results["risk_level"] = "注意"
                results["risk_score"] = 40
       
        # 短縮URLチェック
        short_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
        if any(s in domain for s in short_domains):
            results["warnings"].append("ℹ️ 短縮URLです。実際のリンク先を確認してください")
       
        # 詳細情報
        results["details"].append(f"ドメイン: {domain}")
        results["details"].append(f"プロトコル: {parsed.scheme}")
        results["details"].append(f"パス: {parsed.path or '/'}")
       
    except Exception as e:
        results["risk_level"] = "エラー"
        results["risk_score"] = 0
        results["warnings"].append(f"❌ URL解析エラー: {str(e)}")
   
    return results
 
def analyze_email_local(content):
    """ローカルデータベースでメール解析"""
    results = {
        "risk_level": "安全",
        "risk_score": 10,
        "warnings": [],
        "details": []
    }
   
    # キーワードチェック
    found_keywords = []
    for keyword in st.session_state.threat_database["suspicious_keywords"]:
        if keyword.lower() in content.lower():
            found_keywords.append(keyword)
   
    if found_keywords:
        results["risk_level"] = "注意"
        results["risk_score"] = 50
        results["warnings"].append(f"⚠️ 疑わしいキーワード検出: {', '.join(found_keywords[:3])}")
   
    # URLチェック
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
    if urls:
        results["details"].append(f"検出されたURL数: {len(urls)}")
        dangerous_urls = []
        for url in urls[:5]:
            url_result = analyze_url_local(url)
            if url_result["risk_level"] == "危険":
                results["risk_level"] = "危険"
                results["risk_score"] = 90
                dangerous_urls.append(url)
            elif url_result["risk_level"] == "注意" and results["risk_level"] != "危険":
                results["risk_level"] = "注意"
                results["risk_score"] = max(results["risk_score"], 60)
       
        if dangerous_urls:
            results["warnings"].append(f"🚨 危険なURL発見: {len(dangerous_urls)}件")
   
    # 緊急性チェック
    urgent_words = ["今すぐ", "直ちに", "24時間以内", "immediately", "urgent"]
    if any(word in content.lower() for word in urgent_words):
        results["warnings"].append("⚠️ 緊急性を煽る表現が含まれています")
        results["risk_score"] = min(results["risk_score"] + 20, 100)
   
    return results
 
# タブ1: URLチェック
with tab1:
    st.header("🔍 URL安全性チェック")
   
    col1, col2 = st.columns([2, 1])
   
    with col1:
        url_input = st.text_area(
            "チェックするURLを入力",
            placeholder="https://example.com",
            height=100
        )
       
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            local_check = st.button("🔍 ローカル分析", type="primary", use_container_width=True)
        with col_btn2:
            ai_check = st.button("🤖 AI分析", use_container_width=True)
   
    with col2:
        st.info("""
        **チェックポイント:**
        - スペルミスがないか
        - HTTPSかHTTPか
        - ドメインが本物か
        - 短縮URLでないか
        - 既知の詐欺サイトか
        """)
   
    # ローカル分析
    if local_check and url_input:
        with st.spinner("🔍 分析中..."):
            result = analyze_url_local(url_input)
           
            st.markdown("---")
            st.subheader("📊 分析結果")
           
            # リスクレベル表示
            if result['risk_level'] == '危険':
                st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>このURLは危険です！アクセスしないでください。</p></div>', unsafe_allow_html=True)
            elif result['risk_level'] == '注意':
                st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>注意が必要です。慎重に確認してください。</p></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>このURLは比較的安全です。</p></div>', unsafe_allow_html=True)
           
            st.progress(result['risk_score'] / 100)
           
            col_a, col_b = st.columns(2)
            with col_a:
                st.subheader("⚠️ 警告")
                if result['warnings']:
                    for warning in result['warnings']:
                        st.warning(warning)
                else:
                    st.success("特に問題は検出されませんでした")
           
            with col_b:
                st.subheader("📋 詳細情報")
                for detail in result['details']:
                    st.text(detail)

# AI分析
    if ai_check and url_input:
        if not api_key:
            st.error("❌ AI分析にはGemini APIキーが必要です（サイドバーで設定）")
        else:
            with st.spinner("🤖 AIが分析中..."):
                try:
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel('gemini-1.5-flash')
                   
                    prompt = f"""以下のURLがフィッシング詐欺サイトである可能性を分析してください。
URL: {url_input}
 
以下の形式でJSON形式で回答してください：
{{
  "risk_level": "high/medium/low",
  "risk_score": 0-100の数値,
  "is_suspicious": true/false,
  "indicators": ["疑わしい点のリスト"],
  "recommendation": "ユーザーへの推奨アクション",
  "summary": "分析結果の簡潔な要約"
}}"""
                   
                    response = model.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.2,
                            max_output_tokens=1000,
                        )
                    )
                   
                    json_match = re.search(r'\{[\s\S]*\}', response.text)
                    if json_match:
                        result = json.loads(json_match.group())
                       
                        st.markdown("---")
                        st.subheader("📊 AI分析結果")
                       
                        if result['risk_level'] == 'high':
                            st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        elif result['risk_level'] == 'medium':
                            st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                       
                        st.progress(result['risk_score'] / 100)
                       
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.subheader("🔍 検出された疑わしい点")
                            for i, indicator in enumerate(result['indicators'], 1):
                                st.markdown(f"{i}. {indicator}")
                       
                        with col_b:
                            st.subheader("💡 推奨アクション")
                            st.info(result['recommendation'])
                    else:
                        st.error("❌ 分析結果の解析に失敗しました")
                except Exception as e:
                    st.error(f"❌ エラーが発生しました: {str(e)}")
 
# タブ2: メールチェック
with tab2:
    st.header("📧 メール内容チェック")
   
    col1, col2 = st.columns([2, 1])
   
    with col1:
        email_input = st.text_area(
            "メール本文を入力",
            placeholder="メールの内容を貼り付けてください",
            height=300
        )
       
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            email_local = st.button("🔍 ローカル分析（メール）", type="primary", use_container_width=True)
        with col_btn2:
            email_ai = st.button("🤖 AI分析（メール）", use_container_width=True)
   
    with col2:
        st.info("""
        **チェックポイント:**
        - 緊急性を煽っていないか
        - 個人情報を求めていないか
        - 不自然な日本語はないか
        - リンク先が正規サイトか
        - 疑わしいキーワードがないか
        """)
   
    # ローカル分析
    if email_local and email_input:
        with st.spinner("🔍 分析中..."):
            result = analyze_email_local(email_input)
           
            st.markdown("---")
            st.subheader("📊 分析結果")
           
            if result['risk_level'] == '危険':
                st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>このメールは詐欺の可能性が高いです！</p></div>', unsafe_allow_html=True)
            elif result['risk_level'] == '注意':
                st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>注意が必要です。慎重に確認してください。</p></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>このメールは比較的安全です。</p></div>', unsafe_allow_html=True)
           
            st.progress(result['risk_score'] / 100)
           
            col_a, col_b = st.columns(2)
            with col_a:
                st.subheader("⚠️ 警告")
                if result['warnings']:
                    for warning in result['warnings']:
                        st.warning(warning)
                else:
                    st.success("特に問題は検出されませんでした")
           
            with col_b:
                st.subheader("📋 詳細情報")
                for detail in result['details']:
                    st.text(detail)
   
    # AI分析
    if email_ai and email_input:
        if not api_key:
            st.error("❌ AI分析にはGemini APIキーが必要です")
        else:
            with st.spinner("🤖 AIが分析中..."):
                try:
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel('gemini-1.5-flash')
                   
                    prompt = f"""以下のメール内容がフィッシング詐欺である可能性を分析してください。
メール内容:
{email_input}
 
以下の形式でJSON形式で回答してください：
{{
  "risk_level": "high/medium/low",
  "risk_score": 0-100の数値,
  "is_suspicious": true/false,
  "indicators": ["疑わしい点のリスト"],
  "recommendation": "ユーザーへの推奨アクション",
  "summary": "分析結果の簡潔な要約"
}}"""
                   
                    response = model.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.2,
                            max_output_tokens=1000,
                        )
                    )
                   
                    json_match = re.search(r'\{[\s\S]*\}', response.text)
                    if json_match:
                        result = json.loads(json_match.group())
                       
                        st.markdown("---")
                        st.subheader("📊 AI分析結果")
                       
                        if result['risk_level'] == 'high':
                            st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        elif result['risk_level'] == 'medium':
                            st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                       
                        st.progress(result['risk_score'] / 100)
                       
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.subheader("🔍 検出された疑わしい点")
                            for i, indicator in enumerate(result['indicators'], 1):
                                st.markdown(f"{i}. {indicator}")
                       
                        with col_b:
                            st.subheader("💡 推奨アクション")
                            st.info(result['recommendation'])
                except Exception as e:
                    st.error(f"❌ エラーが発生しました: {str(e)}")
 
# タブ3: 通報・共有
with tab3:
    st.header("📢 怪しいサイト・メールを通報")
   
    with st.form("report_form"):
        report_url = st.text_input("URL", placeholder="https://suspicious-site.com")
        report_detail = st.text_area("詳細情報", placeholder="どのような詐欺の疑いがあるか説明してください", height=150)
        submitted = st.form_submit_button("📢 通報する", type="primary")
       
        if submitted:
            if report_url:
                report = {
                    "url": report_url,
                    "detail": report_detail,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                st.session_state.reported_sites.append(report)
                st.success("✅ 通報ありがとうございます！情報はデータベースに追加されました。")
            else:
                st.error("❌ URLを入力してください")
   
    st.markdown("---")
    st.subheader("📋 最近の通報情報")
   
    if st.session_state.reported_sites:
        for i, report in enumerate(reversed(st.session_state.reported_sites[-10:]), 1):
            with st.expander(f"🚨 通報 #{len(st.session_state.reported_sites) - i + 1} - {report['url'][:50]}..."):
                st.text(f"日時: {report['timestamp']}")
                st.text(f"URL: {report['url']}")
                st.text(f"詳細: {report['detail']}")
    else:
        st.info("まだ通報はありません")
 
# タブ4: 脅威情報
with tab4:
    st.header("⚠️ 脅威情報データベース")
   
    col1, col2 = st.columns([3, 1])
    with col1:
        st.text(f"最終更新: {st.session_state.last_update}")
    with col2:
        if st.button("🔄 更新", use_container_width=True):
            # 通報されたサイトをデータベースに追加
            for report in st.session_state.reported_sites:
                domain = urlparse(report['url']).netloc
                if domain and domain not in st.session_state.threat_database["dangerous_domains"]:
                    st.session_state.threat_database["dangerous_domains"].append(domain)
           
            st.session_state.last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.success("✅ データベースを更新しました！")
            time.sleep(1)
            st.rerun()
   
    st.markdown("---")
   
    col1, col2 = st.columns(2)
   
    with col1:
        st.subheader("🚫 危険なドメイン")
        for i, domain in enumerate(st.session_state.threat_database["dangerous_domains"], 1):
            st.markdown(f'<div class="threat-item">{i}. {domain}</div>', unsafe_allow_html=True)
   
    with col2:
        st.subheader("🔍 疑わしいキーワード")
        for i, keyword in enumerate(st.session_state.threat_database["suspicious_keywords"], 1):
            st.markdown(f'<div class="threat-item">{i}. {keyword}</div>', unsafe_allow_html=True)
 
# フッター
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem;">
    <p>⚠️ このツールは補助的なものです。最終的な判断は慎重に行ってください。</p>
    <p>💡 ローカル分析は無料、AI分析にはGemini APIキーが必要です</p>
    <p>Powered by Google Gemini AI & Local Threat Database</p>
</div>
""", unsafe_allow_html=True)
import streamlit as st
import random

    # 電話番号チェック（仮）
import streamlit as st
import json
import re
from datetime import datetime
import time
import random
# ページ設定
st.set_page_config(
   page_title="📞 電話番号チェッカー",
   page_icon="📞",
   layout="wide"
)
# セッション状態の初期化
if 'check_history' not in st.session_state:
   st.session_state.check_history = []
if 'scam_database' not in st.session_state:
   st.session_state.scam_database = {
       "known_scam_numbers": [
           "03-1234-5678",
           "0120-999-999",
           "050-1111-2222",
           "090-1234-5678"
       ],
       "suspicious_prefixes": [
           "050",  # IP電話（悪用されやすい）
           "070",  # 携帯（最近は詐欺に使用増加）
           "+675", # パプアニューギニア（国際詐欺）
           "+234", # ナイジェリア（国際詐欺）
           "+1-876" # ジャマイカ（国際詐欺）
       ],
       "warning_patterns": [
           r"^0120",  # フリーダイヤル（偽装多い）
           r"^0570",  # ナビダイヤル（高額請求）
           r"^0990",  # 特定サービス
           r"^\+.*"   # 国際電話
       ],
       "safe_prefixes": [
           "110",  # 警察
           "119",  # 消防・救急
           "118",  # 海上保安庁
       ],
       "reported_cases": []
   }
if 'monitoring' not in st.session_state:
   st.session_state.monitoring = False
if 'last_check' not in st.session_state:
   st.session_state.last_check = None
def identify_number_type(normalized):
   """番号タイプ識別"""
   if normalized.startswith('0120') or normalized.startswith('0800'):
       return "フリーダイヤル"
   elif normalized.startswith('050'):
       return "IP電話"
   elif normalized.startswith('090') or normalized.startswith('080') or normalized.startswith('070'):
       return "携帯電話"
   elif normalized.startswith('0570'):
       return "ナビダイヤル"
   elif normalized.startswith('0'):
       return "固定電話"
   elif normalized.startswith('+'):
       return "国際電話"
   else:
       return "不明"
def identify_area(number):
   """地域識別"""
   area_codes = {
       "03": "東京",
       "06": "大阪",
       "052": "名古屋",
       "011": "札幌",
       "092": "福岡",
       "075": "京都"
   }
   for code, area in area_codes.items():
       if number.startswith(code):
           return area
   return "不明"
def analyze_phone_number(number):
   """電話番号解析"""
   normalized = re.sub(r'[-\s()]+', '', number)
   result = {
       "original": number,
       "normalized": normalized,
       "risk_level": "安全",
       "warnings": [],
       "details": [],
       "recommendations": [],
       "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   }
   # 緊急番号チェック
   if normalized in ["110", "119", "118"]:
       result["risk_level"] = "緊急"
       result["details"].append("✅ 緊急通報番号です")
       return result
   # 既知の詐欺番号チェック
   if number in st.session_state.scam_database["known_scam_numbers"]:
       result["risk_level"] = "危険"
       result["warnings"].append("🚨 既知の詐欺電話番号です！")
       result["recommendations"].append("❌ 絶対に応答しないでください")
       result["recommendations"].append("📞 着信拒否設定を推奨")
       return result
   # ユーザー通報データチェック
   for case in st.session_state.scam_database["reported_cases"]:
       if case["number"] == number:
           result["risk_level"] = "危険"
           result["warnings"].append(f"⚠️ {case['reports']}件の通報あり")
           result["details"].append(f"通報内容: {case['description']}")
   # プレフィックスチェック
   for prefix in st.session_state.scam_database["suspicious_prefixes"]:
       if normalized.startswith(prefix):
           if result["risk_level"] == "安全":
               result["risk_level"] = "注意"
           result["warnings"].append(f"⚠️ 疑わしいプレフィックス: {prefix}")
           result["recommendations"].append("慎重に対応してください")
   # パターンチェック
   for pattern in st.session_state.scam_database["warning_patterns"]:
       if re.match(pattern, number):
           if result["risk_level"] == "安全":
               result["risk_level"] = "注意"
           result["warnings"].append("⚠️ 警戒が必要なパターンです")
   # 国際電話チェック
   if number.startswith('+') or normalized.startswith('010'):
       result["warnings"].append("🌍 国際電話です")
       result["recommendations"].append("身に覚えがない場合は応答しない")
       if result["risk_level"] == "安全":
           result["risk_level"] = "注意"
   # 詳細情報
   result["details"].append(f"📱 番号タイプ: {identify_number_type(normalized)}")
   result["details"].append(f"📍 地域: {identify_area(number)}")
   # 安全な場合の推奨事項
   if result["risk_level"] == "安全":
       result["recommendations"].append("✅ 特に問題は検出されませんでした")
       result["recommendations"].append("💡 不審な要求には注意してください")
   # 履歴に追加
   st.session_state.check_history.append(result)
   return result
def display_result(result):
   """結果表示"""
   risk_colors = {
       "安全": "green",
       "注意": "orange",
       "危険": "red",
       "緊急": "blue"
   }
   risk_emoji = {
       "安全": "✅",
       "注意": "⚠️",
       "危険": "🚨",
       "緊急": "🚑"
   }
   color = risk_colors.get(result['risk_level'], "gray")
   emoji = risk_emoji.get(result['risk_level'], "❓")
   # メインの結果表示
   st.markdown(f"## {emoji} リスク判定: :{color}[{result['risk_level']}]")
   col1, col2, col3 = st.columns(3)
   with col1:
       st.metric("📞 電話番号", result['original'])
   with col2:
       st.metric("🔢 正規化", result['normalized'])
   with col3:
       st.metric("🕐 チェック時刻", result['timestamp'])
   st.markdown("---")
   # 警告
   if result['warnings']:
       st.error("### ⚠️ 警告")
       for warning in result['warnings']:
           st.markdown(f"- {warning}")
       st.markdown("")
   # 詳細情報
   if result['details']:
       st.info("### 📋 詳細情報")
       for detail in result['details']:
           st.markdown(f"- {detail}")
       st.markdown("")
   # 推奨事項
   if result['recommendations']:
       if result['risk_level'] == "危険":
           st.error("### 💡 推奨事項")
       else:
           st.success("### 💡 推奨事項")
       for rec in result['recommendations']:
           st.markdown(f"- {rec}")
def show_stats():
   """統計情報表示"""
   total = len(st.session_state.check_history)
   dangerous = sum(1 for r in st.session_state.check_history if r['risk_level'] == '危険')
   warning = sum(1 for r in st.session_state.check_history if r['risk_level'] == '注意')
   safe = sum(1 for r in st.session_state.check_history if r['risk_level'] == '安全')
   col1, col2, col3, col4 = st.columns(4)
   col1.metric("📊 総チェック数", total)
   col2.metric("🚨 詐欺検出", dangerous)
   col3.metric("⚠️ 警告", warning)
   col4.metric("✅ 安全", safe)
# メインUI
st.title("📞 リアルタイム電話番号チェッカー")
st.markdown("電話番号の安全性をリアルタイムでチェックします")
# サイドバー
with st.sidebar:
   st.header("🛠️ メニュー")
   page = st.radio(
       "ページ選択",
       ["🔍 番号チェック", "📊 統計情報", "📢 通報", "🗄️ データベース", "ℹ️ 使い方"]
   )
   st.markdown("---")
   # 統計サマリー
   st.subheader("📈 簡易統計")
   show_stats()
   st.markdown("---")
   # リアルタイム監視
   st.subheader("👁️ リアルタイム監視")
   if st.button("🟢 監視開始" if not st.session_state.monitoring else "🔴 監視停止"):
       st.session_state.monitoring = not st.session_state.monitoring
   if st.session_state.monitoring:
       st.success("監視中...")
       # シミュレーション用テストボタン
       if st.button("🎲 着信シミュレート"):
           test_numbers = [
               "090-1234-5678",
               "03-5555-6666",
               "050-9999-8888",
               "+1-876-555-1234"
           ]
           test_number = random.choice(test_numbers)
           st.session_state.last_check = analyze_phone_number(test_number)
           st.rerun()
   else:
       st.info("停止中")
# メインコンテンツ
if page == "🔍 番号チェック":
   st.header("🔍 電話番号チェック")
   # 入力フォーム
   col1, col2 = st.columns([3, 1])
   with col1:
       phone_input = st.text_input(
           "電話番号を入力してください",
           placeholder="例: 090-1234-5678, 03-1234-5678, +81-90-1234-5678",
           key="phone_input"
       )
   with col2:
       st.markdown("<br>", unsafe_allow_html=True)
       check_btn = st.button("🔍 チェック", use_container_width=True)
   if check_btn and phone_input:
       with st.spinner("解析中..."):
           result = analyze_phone_number(phone_input)
           st.session_state.last_check = result
       # 危険な場合は警告音（テキストで表現）
       if result['risk_level'] == "危険":
           st.markdown("### 🚨🚨🚨 警告！ 🚨🚨🚨")
   # 最新の結果表示
   if st.session_state.last_check:
       st.markdown("---")
       st.subheader("📋 チェック結果")
       display_result(st.session_state.last_check)
   # サンプル番号でテスト
   st.markdown("---")
   st.subheader("🧪 サンプル番号でテスト")
   sample_col1, sample_col2, sample_col3, sample_col4 = st.columns(4)
   with sample_col1:
       if st.button("✅ 安全な番号"):
           result = analyze_phone_number("03-5555-6666")
           st.session_state.last_check = result
           st.rerun()
   with sample_col2:
       if st.button("⚠️ 注意が必要"):
           result = analyze_phone_number("050-1111-2222")
           st.session_state.last_check = result
           st.rerun()
   with sample_col3:
       if st.button("🚨 詐欺番号"):
           result = analyze_phone_number("090-1234-5678")
           st.session_state.last_check = result
           st.rerun()
   with sample_col4:
       if st.button("🌍 国際詐欺"):
           result = analyze_phone_number("+1-876-555-1234")
           st.session_state.last_check = result
           st.rerun()
elif page == "📊 統計情報":
   st.header("📊 統計情報")
   show_stats()
   st.markdown("---")
   # チェック履歴
   st.subheader("📜 チェック履歴")
   if st.session_state.check_history:
       # 最新10件を表示
       for i, record in enumerate(reversed(st.session_state.check_history[-10:]), 1):
           with st.expander(f"{i}. {record['original']} - {record['risk_level']} ({record['timestamp']})"):
               display_result(record)
   else:
       st.info("まだチェック履歴がありません")
   # データクリア
   if st.button("🗑️ 履歴をクリア"):
       st.session_state.check_history = []
       st.success("履歴をクリアしました")
       st.rerun()
elif page == "📢 通報":
   st.header("📢 怪しい電話番号を通報")
   st.markdown("""
   詐欺や迷惑電話の可能性がある番号を通報してください。
   通報情報は他のユーザーと共有され、詐欺被害の防止に役立ちます。
   """)
   with st.form("report_form"):
       report_number = st.text_input("電話番号", placeholder="例: 090-1234-5678")
       report_detail = st.text_area(
           "詳細情報",
           placeholder="どのような内容の電話でしたか？具体的に記入してください。",
           height=150
       )
       report_category = st.selectbox(
           "分類",
           ["詐欺", "迷惑営業", "無言電話", "その他"]
       )
       submitted = st.form_submit_button("📢 通報する")
       if submitted and report_number:
           # 通報情報を追加
           report = {
               "number": report_number,
               "description": f"[{report_category}] {report_detail}",
               "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "reports": 1
           }
           # 既存の通報があるか確認
           existing = None
           for case in st.session_state.scam_database["reported_cases"]:
               if case["number"] == report_number:
                   existing = case
                   break
           if existing:
               existing["reports"] += 1
               existing["description"] += f"\n[追加通報 {existing['reports']}] {report_detail}"
           else:
               st.session_state.scam_database["reported_cases"].append(report)
           st.success("✅ 通報ありがとうございます！情報はデータベースに追加されました。")
   # 通報履歴
   st.markdown("---")
   st.subheader("📋 最近の通報情報")
   if st.session_state.scam_database["reported_cases"]:
       for case in reversed(st.session_state.scam_database["reported_cases"][-5:]):
           with st.expander(f"📞 {case['number']} ({case['reports']}件の通報)"):
               st.markdown(f"**通報日時:** {case['timestamp']}")
               st.markdown(f"**詳細:**\n{case['description']}")
   else:
       st.info("まだ通報情報がありません")
elif page == "🗄️ データベース":
   st.header("🗄️ 詐欺電話データベース")
   tab1, tab2, tab3 = st.tabs(["既知の詐欺番号", "疑わしいプレフィックス", "通報された番号"])
   with tab1:
       st.subheader("🚨 既知の詐欺番号")
       for i, number in enumerate(st.session_state.scam_database["known_scam_numbers"], 1):
           st.markdown(f"{i}. `{number}`")
       # 追加機能
       st.markdown("---")
       with st.form("add_scam_number"):
           new_number = st.text_input("新しい詐欺番号を追加")
           if st.form_submit_button("➕ 追加"):
               if new_number and new_number not in st.session_state.scam_database["known_scam_numbers"]:
                   st.session_state.scam_database["known_scam_numbers"].append(new_number)
                   st.success(f"✅ {new_number} を追加しました")
                   st.rerun()
   with tab2:
       st.subheader("⚠️ 疑わしいプレフィックス")
       for prefix in st.session_state.scam_database["suspicious_prefixes"]:
           st.markdown(f"- `{prefix}`")
   with tab3:
       st.subheader("📢 ユーザー通報された番号")
       if st.session_state.scam_database["reported_cases"]:
           for case in st.session_state.scam_database["reported_cases"]:
               st.markdown(f"**{case['number']}** ({case['reports']}件)")
               st.caption(case['description'][:100] + "...")
       else:
           st.info("まだ通報がありません")
else:  # 使い方
   st.header("ℹ️ 使い方ガイド")
   st.markdown("""
   ## 📱 電話番号チェッカーの使い方
   ### 🔍 基本的な使い方
   1. **番号チェック**
      - 左サイドバーから「🔍 番号チェック」を選択
      - 電話番号を入力して「チェック」ボタンをクリック
      - 結果が表示されます
   2. **リアルタイム監視**
      - サイドバーの「監視開始」ボタンをクリック
      - 着信があると自動的にチェックされます（現在はシミュレーション）
   3. **通報機能**
      - 怪しい電話番号を見つけたら「📢 通報」ページから通報
      - 情報は他のユーザーと共有されます
   ### 🎯 リスクレベルの意味
   - **✅ 安全**: 特に問題は検出されませんでした
   - **⚠️ 注意**: 疑わしい特徴があります。慎重に対応してください
   - **🚨 危険**: 詐欺の可能性が高いです。応答しないでください
   - **🚑 緊急**: 緊急通報番号です
   ### 💡 詐欺電話の見分け方
   1. **身に覚えのない国際電話**
   2. **IP電話からの不審な着信**
   3. **フリーダイヤルからの執拗な着信**
   4. **個人情報や金銭を要求する内容**
   5. **緊急性を装った内容**
   ### 🛡️ 対策方法
   - 不審な番号には出ない
   - 留守番電話で内容を確認
   - 着信拒否設定を活用
   - 個人情報は絶対に教えない
   - おかしいと思ったらすぐに電話を切る
   ### 📞 相談窓口
   - **警察相談専用電話**: #9110
   - **消費者ホットライン**: 188
   - **金融庁**: 0570-016811
   """)
   st.info("💡 このアプリはデモ版です。実際の運用には、より高度なデータベースとAPI連携が必要です。")
# フッター
st.markdown("---")
st.caption("⚠️ このアプリは詐欺電話対策の補助ツールです。最終的な判断はご自身で行ってください。")

st.header('詐欺の特徴')
st.write('特徴を知りたい詐欺の種類を選択してください')
if st.button('サイトによる詐欺'):
    st.write('特徴')
    st.write('・不自然な日本語：翻訳されたような不自然な言い回しや誤字脱字が多い')
    st.write('・異常な安さ　　：他社と比較して極端に安い価格設定になっている')
    st.write('・甘い言葉　　　：「必ずもうかる」「高額当選」など、うまい話で誘い出す　等…')
elif st.button('メールによる詐欺'):
    st.write('')
elif st.button('電話による詐欺'):
    st.write('')