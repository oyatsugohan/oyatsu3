import streamlit as st
import re
import json
from datetime import datetime
from urllib.parse import urlparse
import random

# Gemini APIのインポート（オプション）
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# ページ設定
st.set_page_config(
    page_title="統合セキュリティチェッカー",
    page_icon="🔒",
    layout="wide"
)

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
            "本人確認", "パスワード更新", "セキュリティ警告",
            "一時停止", "24時間以内", "今すぐ"
        ],
        "dangerous_patterns": [
            r"http://[^/]*\.(tk|ml|ga|cf|gq)",
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
            r"https?://[^/]*-[^/]*(login|signin|verify)",
        ]
    }

if 'reported_sites' not in st.session_state:
    st.session_state.reported_sites = []

if 'check_history' not in st.session_state:
    st.session_state.check_history = []

if 'quiz_index' not in st.session_state:
    st.session_state.quiz_index = 0
   
if 'score' not in st.session_state:
    st.session_state.score = 0
   
if 'answered' not in st.session_state:
    st.session_state.answered = False

# クイズサンプルデータ
quiz_samples = [
    {
        "subject": "【重要】あなたのアカウントが一時停止されました",
        "content": "お客様のアカウントに不審なアクセスが検出されました。以下のリンクから確認してください。\n→ http://security-update-login.com",
        "is_phishing": True,
        "explanation": "正規のドメインではなく、不審なURLを使用しています。緊急性を煽る表現も典型的なフィッシングの手口です。"
    },
    {
        "subject": "【Amazon】ご注文ありがとうございます",
        "content": "ご注文いただいた商品は10月12日に発送されます。ご利用ありがとうございます。",
        "is_phishing": False,
        "explanation": "内容は自然で、URLも含まれていません。正規の連絡の可能性が高いです。"
    },
    {
        "subject": "【Apple ID】アカウント情報の確認が必要です",
        "content": "セキュリティのため、以下のURLから24時間以内に情報を更新してください。\n→ http://apple.login-check.xyz",
        "is_phishing": True,
        "explanation": "URLが公式のAppleドメインではありません。典型的なフィッシングサイトの形式です。"
    },
    {
        "subject": "【楽天】ポイント還元のお知らせ",
        "content": "キャンペーンにより、300ポイントを付与しました。楽天市場をご利用いただきありがとうございます。",
        "is_phishing": False,
        "explanation": "不自然なURLや情報要求がなく、自然な表現です。"
    },
]

# 関数定義
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
                results["warnings"].append("⚠️ 疑わしいURLパターンを検出")
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

def analyze_phone_number(phone):
    """電話番号チェック"""
    results = {
        "phone": phone,
        "risk_level": "安全",
        "risk_score": 10,
        "warnings": [],
        "details": []
    }
    
    # 数字のみ抽出
    clean_phone = re.sub(r'\D', '', phone)
    
    # 既知の詐欺番号パターン（例）
    scam_prefixes = ['0120', '0800', '050']  # 実際にはもっと詳細なデータベースが必要
    
    if len(clean_phone) < 10:
        results["warnings"].append("⚠️ 電話番号が短すぎます")
        results["risk_level"] = "注意"
        results["risk_score"] = 40
    
    # プレフィックスチェック
    for prefix in scam_prefixes:
        if clean_phone.startswith(prefix):
            results["details"].append(f"📞 {prefix}番号です（フリーダイヤル/IP電話）")
    
    results["details"].append(f"クリーン番号: {clean_phone}")
    results["details"].append(f"桁数: {len(clean_phone)}")
    
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

def analyze_with_gemini(prompt, api_key):
    """Gemini AIで分析"""
    if not GEMINI_AVAILABLE:
        return None
   
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
       
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.2,
                max_output_tokens=1000,
            )
        )
       
        json_match = re.search(r'\{[\s\S]*\}', response.text)
        if json_match:
            return json.loads(json_match.group())
        return None
    except Exception as e:
        st.error(f"❌ AI分析エラー: {str(e)}")
        return None

def display_result(result):
    """結果表示"""
    if result['risk_level'] == '危険':
        st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3></div>', unsafe_allow_html=True)
    elif result['risk_level'] == '注意':
        st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3></div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3></div>', unsafe_allow_html=True)
   
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

# ヘッダー
st.markdown("""
<div class="main-header">
    <h1>🔒 統合セキュリティチェッカー</h1>
    <p>詐欺・フィッシング対策のための包括的なセキュリティツール</p>
</div>
""", unsafe_allow_html=True)

# サイドバー
with st.sidebar:
    st.header("⚙️ 設定")
    
    # Gemini API設定
    use_gemini = st.checkbox("🤖 Gemini AIを使用", value=False)
    gemini_api_key = None
    
    if use_gemini:
        gemini_api_key = st.text_input(
            "Gemini APIキー",
            type="password",
            help="Google AI StudioでAPIキーを取得できます"
        )
        if not GEMINI_AVAILABLE:
            st.error("❌ google-generativeaiがインストールされていません")
    
    st.divider()
    
    # 統計情報
    st.subheader("📊 統計")
    st.metric("チェック履歴", len(st.session_state.check_history))
    st.metric("報告されたサイト", len(st.session_state.reported_sites))

# メインコンテンツ
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔗 URLチェック",
    "📧 メール分析",
    "📞 電話番号チェック",
    "🎯 フィッシングクイズ",
    "📚 学習リソース"
])

# タブ1: URLチェック
with tab1:
    st.header("🔗 URLセキュリティチェック")
    
    url_input = st.text_input(
        "チェックしたいURLを入力してください",
        placeholder="https://example.com"
    )
    
    if st.button("🔍 URLをチェック", key="check_url"):
        if url_input:
            with st.spinner("分析中..."):
                # ローカル分析
                local_result = analyze_url_local(url_input)
                
                st.subheader("📊 ローカル分析結果")
                display_result(local_result)
                
                # Gemini分析
                if use_gemini and gemini_api_key:
                    prompt = f"""
                    以下のURLのセキュリティを分析してください。
                    URL: {url_input}
                    
                    以下のJSON形式で回答してください：
                    {{
                        "risk_level": "安全/注意/危険",
                        "risk_score": 0-100の数値,
                        "warnings": ["警告1", "警告2"],
                        "details": ["詳細1", "詳細2"]
                    }}
                    """
                    
                    ai_result = analyze_with_gemini(prompt, gemini_api_key)
                    if ai_result:
                        st.subheader("🤖 AI分析結果")
                        display_result(ai_result)
                
                # 履歴に追加
                st.session_state.check_history.append({
                    "type": "URL",
                    "content": url_input,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "result": local_result
                })
        else:
            st.warning("URLを入力してください")

# タブ2: メール分析
with tab2:
    st.header("📧 メール・メッセージ分析")
    
    email_subject = st.text_input("件名（オプション）")
    email_content = st.text_area(
        "メール本文を貼り付けてください",
        height=200,
        placeholder="メールやメッセージの内容をここに貼り付けてください"
    )
    
    if st.button("🔍 メールを分析", key="check_email"):
        if email_content:
            with st.spinner("分析中..."):
                full_content = f"{email_subject}\n{email_content}" if email_subject else email_content
                
                # ローカル分析
                local_result = analyze_email_local(full_content)
                
                st.subheader("📊 ローカル分析結果")
                display_result(local_result)
                
                # Gemini分析
                if use_gemini and gemini_api_key:
                    prompt = f"""
                    以下のメール内容がフィッシング詐欺かどうか分析してください。
                    
                    件名: {email_subject}
                    本文: {email_content}
                    
                    以下のJSON形式で回答してください：
                    {{
                        "risk_level": "安全/注意/危険",
                        "risk_score": 0-100の数値,
                        "warnings": ["警告1", "警告2"],
                        "details": ["詳細1", "詳細2"]
                    }}
                    """
                    
                    ai_result = analyze_with_gemini(prompt, gemini_api_key)
                    if ai_result:
                        st.subheader("🤖 AI分析結果")
                        display_result(ai_result)
                
                # 履歴に追加
                st.session_state.check_history.append({
                    "type": "Email",
                    "content": full_content[:100] + "...",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "result": local_result
                })
        else:
            st.warning("メール本文を入力してください")

# タブ3: 電話番号チェック
with tab3:
    st.header("📞 電話番号チェック")
    
    phone_input = st.text_input(
        "電話番号を入力してください",
        placeholder="090-1234-5678 または 09012345678"
    )
    
    if st.button("🔍 電話番号をチェック", key="check_phone"):
        if phone_input:
            with st.spinner("分析中..."):
                # ローカル分析
                local_result = analyze_phone_number(phone_input)
                
                st.subheader("📊 分析結果")
                display_result(local_result)
                
                # Gemini分析
                if use_gemini and gemini_api_key:
                    prompt = f"""
                    以下の電話番号について、詐欺の可能性を分析してください。
                    電話番号: {phone_input}
                    
                    以下のJSON形式で回答してください：
                    {{
                        "risk_level": "安全/注意/危険",
                        "risk_score": 0-100の数値,
                        "warnings": ["警告1", "警告2"],
                        "details": ["詳細1", "詳細2"]
                    }}
                    """
                    
                    ai_result = analyze_with_gemini(prompt, gemini_api_key)
                    if ai_result:
                        st.subheader("🤖 AI分析結果")
                        display_result(ai_result)
                
                # 履歴に追加
                st.session_state.check_history.append({
                    "type": "Phone",
                    "content": phone_input,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "result": local_result
                })
        else:
            st.warning("電話番号を入力してください")

# タブ4: フィッシングクイズ
with tab4:
    st.header("🎯 フィッシング詐欺見分けクイズ")
    st.write("実際のメッセージを見て、フィッシング詐欺かどうか判断してみましょう！")
    
    if st.session_state.quiz_index < len(quiz_samples):
        quiz = quiz_samples[st.session_state.quiz_index]
        
        st.subheader(f"問題 {st.session_state.quiz_index + 1}/{len(quiz_samples)}")
        
        st.info(f"**件名:** {quiz['subject']}")
        st.text_area("本文:", quiz['content'], height=150, disabled=True)
        
        if not st.session_state.answered:
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("✅ 安全なメール", use_container_width=True):
                    st.session_state.answered = True
                    if not quiz['is_phishing']:
                        st.session_state.score += 1
                        st.success("✅ 正解！")
                    else:
                        st.error("❌ 不正解")
                    st.info(f"**解説:** {quiz['explanation']}")
                    
            with col2:
                if st.button("⚠️ フィッシング詐欺", use_container_width=True):
                    st.session_state.answered = True
                    if quiz['is_phishing']:
                        st.session_state.score += 1
                        st.success("✅ 正解！")
                    else:
                        st.error("❌ 不正解")
                    st.info(f"**解説:** {quiz['explanation']}")
        
        else:
            st.info(f"**解説:** {quiz['explanation']}")
            if st.button("➡️ 次の問題へ"):
                st.session_state.quiz_index += 1
                st.session_state.answered = False
                st.rerun()
    
    else:
        st.balloons()
        st.success(f"🎉 クイズ完了！ スコア: {st.session_state.score}/{len(quiz_samples)}")
        
        if st.button("🔄 もう一度挑戦"):
            st.session_state.quiz_index = 0
            st.session_state.score = 0
            st.session_state.answered = False
            st.rerun()

# タブ5: 学習リソース
with tab5:
    st.header("📚 詐欺対策学習リソース")
    
    st.subheader("🎓 フィッシング詐欺の見分け方")
    
    with st.expander("1️⃣ URLを確認する"):
        st.write("""
        - 公式サイトのドメイン名を確認
        - HTTPSかどうかチェック
        - 不自然なドメイン（例：paypa1.com）に注意
        """)
    
    with st.expander("2️⃣ 緊急性を煽る表現に注意"):
        st.write("""
        - 「24時間以内に」「今すぐ」などの言葉
        - アカウント停止の脅し
        - 不自然な日本語表現
        """)
    
    with st.expander("3️⃣ 個人情報の要求"):
        st.write("""
        - 正規の企業はメールでパスワードを聞かない
        - クレジットカード情報の直接入力要求
        - 暗証番号の問い合わせ
        """)
    
    with st.expander("4️⃣ 送信者を確認"):
        st.write("""
        - メールアドレスのドメインが公式か
        - 不自然な送信者名
        - 返信先アドレスの確認
        """)
    
    st.divider()
    
    st.subheader("🔗 参考リンク")
    st.markdown("""
    - [警察庁 サイバー犯罪対策](https://www.npa.go.jp/cyber/)
    - [フィッシング対策協議会](https://www.antiphishing.jp/)
    - [消費者庁 詐欺情報](https://www.caa.go.jp/)
    """)

# フッター
st.divider()
st.markdown("""
<div style='text-align: center; color: #666; padding: 1rem;'>
    <p>⚠️ このツールは参考情報です。不審なメッセージは専門機関にご相談ください。</p>
    <p>© 2024 統合セキュリティチェッカー</p>
</div>
""", unsafe_allow_html=True)