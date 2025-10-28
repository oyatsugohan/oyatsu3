import streamlit as st
import re
from urllib.parse import urlparse
import google.generativeai as genai
 
# ページ設定
st.set_page_config(
    page_title="詐欺対策総合アプリ (AI搭載)",
    page_icon="🛡️",
    layout="wide"
)
 
# セッション状態の初期化
if 'quiz_index' not in st.session_state:
    st.session_state.quiz_index = 0
if 'quiz_score' not in st.session_state:
    st.session_state.quiz_score = 0
if 'quiz_answered' not in st.session_state:
    st.session_state.quiz_answered = False
if 'gemini_api_key' not in st.session_state:
    st.session_state.gemini_api_key = ""
 
# クイズデータ
QUIZ_SAMPLES = [
    {
        "subject": "【重要】あなたのアカウントが一時停止されました",
        "content": "お客様のアカウントに不審なアクセスが検出されました。以下のリンクから確認してください。\n→ http://security-update-login.com",
        "isPhishing": True,
        "explanation": "正規のドメインではなく、不審なURLを使用しています。"
    },
    {
        "subject": "【Amazon】ご注文ありがとうございます",
        "content": "ご注文いただいた商品は10月12日に発送されます。ご利用ありがとうございます。",
        "isPhishing": False,
        "explanation": "内容は自然で、URLも含まれていません。正規の連絡の可能性が高いです。"
    },
    {
        "subject": "【Apple ID】アカウント情報の確認が必要です",
        "content": "セキュリティのため、以下のURLから24時間以内に情報を更新してください。\n→ http://apple.login-check.xyz",
        "isPhishing": True,
        "explanation": "URLが公式のAppleドメインではありません。典型的なフィッシングサイトの形式です。"
    }
]
 
# Gemini AI初期化
def init_gemini(api_key):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash-exp')
        return model
    except Exception as e:
        return None
 
# Gemini AIで電話番号分析
def analyze_phone_with_ai(number, model):
    prompt = f"""
あなたは詐欺対策の専門家です。以下の電話番号を分析し、JSON形式で回答してください。

電話番号: {number}

以下の項目を分析してください:
⒈　リスクレベル（危険/注意/安全/緊急）
⒉　リスクスコア（0-100）
⒊　発信者タイプ（個人携帯/企業/公的機関/IP電話/国際電話など）
⒋　警告メッセージ　（あれば）
⒌　詳細情報

回答は必ず以下のJSON形式で
{{
    "risk_level":"注意",
    "risk_score":60,
    "caller_type":"IP電話利用者",
    "warnings":["警告１","警告２"]
    "ai_analysis":"AIによる総合分析"
}}
"""
   
    try:
        response = model.generate_content(prompt)
        import json
        result_text = response.text.strip()
        
        # JSONブロックの抽出
        if '```json' in result_text:
            result_text = result_text.split('```json')[1].split('```')[0].strip()
        elif '```' in result_text:
            result_text = result_text.split('```')[1].split('```')[0].strip()
        

        result = json.loads(result_text)
        result['number'] = number
        result['ai_powered'] = True
        return result
    except Exception as e:
        st.error(f"AI分析エラー：{str(e)}")
        return None

 
# Gemini AIでURL分析
def analyze_url_with_ai(url, model):
    prompt = f"""
あなたはサイバーセキュリティの専門家です。以下のURLを分析し、JSON形式で回答してください。

URL: {url}

以下の項目を分析してください
⒈　リスクレベル（危険/注意/安全）
⒉　リスクスコア（0-100）
⒊　HTTPSの使用有無
⒋　警告メッセージ（あれば）
⒌　詳細情報

回答は必ず以下のJSON形式で:
{{
    "risk_level": "注意",
    "risk_score": 60,
    "warnings": ["警告１","警告２"],
    "details": ["詳細情報のリスト"],
    "ai_analysis": "AIによる総合分析"
}}

JSON以外の文章は出力しないでください。
"""
   
    try:
        response = model.generate_content(prompt)
        import json
        result_text = response.text.strip()
        
        if '```json' in result_text:
            result_text = result_text.split('```json')[1].split('```')[0].strip()
        elif '```' in result_text:
            result_text = result_text.split('```')[1].split('```')[0].strip()
        

        result = json.loads(result_text)
        result['url'] = url
        result['ai_powered'] = True
        return result
    except Exception as e:
        st.error(f"AI分析エラー：{str(e)}")
        return None
 
# Gemini AIでメール分析
def analyze_email_with_ai(content, model):
    prompt = f"""
あなたはフィッシング詐欺対策の専門家です。以下のメール内容を分析し、JSON形式で回答してください。

メール内容:
{content}

以下の項目を分析してください:
⒈　フィッシング詐欺の可能性（危険/注意/安全）
⒉　リスクスコア（0-100）
⒊　検出された疑わしいキーワード
⒋　緊急性をあおる表現の有無
⒌　URLの安全性
⒍　警告メッセージ（あれば）
⒎　詳細な分析結果

回答は必ず以下のJSON形式で:
{{
    "risk_level": "注意",
    "risk_score": 60,
    "warnings": ["警告１","警告２"],
    "details": ["詳細１","詳細２"],
    "ai_analysis": "AIによる総合分析と推奨事項"
}}
"""
   
    try:
        response = model.generate_content(prompt)
        import json
        result_text = response.text.strip()

        if '```json' in result_text:
            result_text = result_text.split('```json')[1].split('```')[0].strip()
        elif '```' in result_text:
            result_text = result_text.split('```')[1].split('```')[0].strip()
        
        result = json.loads(result_text)
        result['ai_powered'] = True
        return result
    except Exception as e:
        st.error(f"AI分析エラー:{str(e)}")
        return None
 
# 従来の電話番号分析関数（フォールバック用）
def analyze_phone_number(number):
    normalized = re.sub(r'[-\s()]+', '', number)
    risk_level = '安全'
    risk_score = 10
    warnings = []
    details = []
    caller_type = '不明'
   
    # 緊急番号チェック
    if normalized in ['110', '119', '118']:
        caller_type = '緊急通報番号'
        risk_level = '緊急'
        details.append('✅ 緊急通報番号です')
    # 公的機関パターン
    elif normalized.startswith('033581') or normalized.startswith('0800'):
        caller_type = '公的機関'
        details.append('🏛️ 官公庁の番号パターン')
    # フリーダイヤル
    elif normalized.startswith('0120') or normalized.startswith('0800'):
        caller_type = '企業カスタマーサポート'
        details.append('📞 フリーダイヤル（通話無料）')
    # IP電話（要注意）
    elif normalized.startswith('050'):
        caller_type = 'IP電話利用者'
        warnings.append('⚠️ IP電話は匿名性が高く、詐欺に悪用されやすい')
        risk_level = '注意'
        risk_score = 60
    # 携帯電話
    elif normalized.startswith(('090', '080', '070')):
        caller_type = '個人携帯電話'
        details.append('📱 個人契約の携帯電話')
    # 国際電話
    elif number.startswith('+') or normalized.startswith('010'):
        caller_type = '国際電話'
        warnings.append('🌍 国際電話 - 身に覚えがない場合は応答しない')
        risk_level = '注意'
        risk_score = 70
    # 固定電話
    elif normalized.startswith('0'):
        caller_type = '固定電話'
        details.append('🏢 固定電話（企業または個人宅）')
   
    # 既知の詐欺番号パターン
    scam_numbers = ['0312345678', '0120999999', '05011112222']
    if any(scam in normalized for scam in scam_numbers):
        risk_level = '危険'
        risk_score = 95
        warnings.append('🚨 既知の詐欺電話番号です！絶対に応答しないでください')
   
    return {
        'number': number,
        'normalized': normalized,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'warnings': warnings,
        'details': details,
        'caller_type': caller_type,
        'ai_powered': False
    }
 
# URL分析関数（フォールバック用）
def analyze_url(url):
    risk_level = '安全'
    risk_score = 10
    warnings = []
    details = []
   
    try:
        parsed = urlparse(url)
        details.append(f"ドメイン: {parsed.hostname}")
        details.append(f"プロトコル: {parsed.scheme}")
       
        # HTTPSチェック
        if parsed.scheme == 'http':
            warnings.append('⚠️ HTTPSではありません（通信が暗号化されていません）')
            risk_level = '注意'
            risk_score = 40
       
        # 危険なドメインパターン
        dangerous_domains = ['paypal-secure-login', 'amazon-verify', 'apple-support-id']
        if any(d in parsed.hostname for d in dangerous_domains):
            warnings.append('🚨 既知の詐欺サイトのパターンです！')
            risk_level = '危険'
            risk_score = 95
       
        # IPアドレスチェック
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.hostname):
            warnings.append('⚠️ IPアドレスが使用されています')
            risk_level = '注意'
            risk_score = max(risk_score, 60)
       
        # 短縮URLチェック
        short_domains = ['bit.ly', 'tinyurl.com', 't.co']
        if any(s in parsed.hostname for s in short_domains):
            warnings.append('ℹ️ 短縮URLです。実際のリンク先を確認してください')
   
    except:
        warnings.append('❌ 無効なURL形式です')
        risk_level = 'エラー'
        risk_score = 0
   
    return {
        'url': url,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'warnings': warnings,
        'details': details,
        'ai_powered': False
    }
 
# メール分析関数（フォールバック用）
def analyze_email(content):
    risk_level = '安全'
    risk_score = 10
    warnings = []
    details = []
   
    # 疑わしいキーワード
    suspicious_keywords = ['verify account', 'urgent action', 'suspended', 'アカウント確認', '緊急', '本人確認', 'パスワード更新']
    found_keywords = [k for k in suspicious_keywords if k.lower() in content.lower()]
   
    if found_keywords:
        warnings.append(f"⚠️ 疑わしいキーワード検出: {', '.join(found_keywords[:3])}")
        risk_level = '注意'
        risk_score = 50
   
    # URL検出
    url_matches = re.findall(r'https?://[^\s<>"]+', content)
    if url_matches:
        details.append(f"検出されたURL数: {len(url_matches)}")
        for url in url_matches[:2]:
            url_analysis = analyze_url(url)
            if url_analysis['risk_level'] == '危険':
                risk_level = '危険'
                risk_score = 90
                warnings.append('🚨 危険なURLが含まれています')
   
    # 緊急性を煽る表現
    urgent_words = ['今すぐ', '直ちに', '24時間以内', 'immediately', 'urgent']
    if any(w.lower() in content.lower() for w in urgent_words):
        warnings.append('⚠️ 緊急性を煽る表現が含まれています')
        risk_score = min(risk_score + 20, 100)
   
    return {
        'risk_level': risk_level,
        'risk_score': risk_score,
        'warnings': warnings,
        'details': details,
        'ai_powered': False
    }
 
# リスク表示関数
def display_risk_result(result):
    # カラー設定
    color_map = {
        '危険': 'red',
        '注意': 'orange',
        '緊急': 'blue',
        '安全': 'green'
    }
    color = color_map.get(result['risk_level'], 'gray')
   
    # AI分析バッジ
    if result.get('ai_powered', False):
        st.success("🤖 Gemini AI による高度な分析結果")
    else:
        st.info("📊 ルールベース分析結果")
   
    st.markdown(f"### リスク判定: :{color}[{result['risk_level']}]")
    st.metric("リスクスコア", f"{result['risk_score']}/100")
   
    # 発信者タイプ（電話番号の場合）
    if 'caller_type' in result:
        st.info(f"**📞 発信者タイプ:** {result['caller_type']}")
   
    # AI分析結果
    if 'ai_analysis' in result:
        st.success(f"**🤖 AI総合分析**\n\n{result['ai_analysis']}")
   
    # 警告
    if result.get('warnings'):
        st.warning("**⚠️ 警告**\n\n" + "\n\n".join(result['warnings']))
   
    # 詳細情報
    if result.get('details'):
        with st.expander("📋 詳細情報"):
            for detail in result['details']:
                st.write(detail)
 
# メインアプリ
def main():
    st.title("🛡️ 詐欺対策総合アプリ (Gemini AI搭載)")
    st.markdown("電話・メール・URLの安全性を**AI**と従来手法で多角的にチェック")
   
    # サイドバーでAPI設定
    with st.sidebar:
        st.header("⚙️ 設定")
       
        st.info("🤖 使用モデル: **Gemini 2.0 Flash (実験版)**")
       
        api_key = st.text_input(
            "Gemini API キー",
            type="password",
            value=st.session_state.gemini_api_key,
            help="https://aistudio.google.com/app/apikey から取得"
        )

        if api_key != st.session_state.gemini_api_key:
            st.session_state/gemini_api_key = api_key
        
        #APIキーが有効かチェック
        model = None
        use_ai = False
        if api_key:
            model = init_gemini(api_key)
            if model:
                use_ai = st.checkbox("🤖AI分析を使用",value=True)
                st.success("✅AI分析が有効です")
            else:
                st.error("✖APIキーが無効です。正しいキーを入力してください")
        else:
            st.warning("⚠️APIキーを入力するとAI分析が有効になります")
        
        st.divider()

        # タブ選択
        tab = st.radio(
            "メニュー",
            ["🏠 ホーム", "📞 電話番号チェック", "🔗 URLチェック", "📧 メールチェック", "❓ 学習クイズ", "💾 脅威データベース", "📖 使い方ガイド"]
        )
   
    # ホーム画面
    if tab == "🏠 ホーム":
        col1, col2 = st.columns(2)
       
        with col1:
            st.info("""
            ### 📞 電話番号チェック
            詐欺電話の可能性をAIで分析
            """)
           
            st.success("""
            ### 🔗 URLチェック
            フィッシングサイトをAIで検出
            """)
       
        with col2:
            st.warning("""
            ### 📧 メールチェック
            詐欺メールの特徴をAIで分析
            """)
           
            st.error("""
            ### ❓ 学習クイズ
            詐欺を見抜く力をつける
            """)
       
        st.info("""
        ### 🤖 AI搭載の主な機能
        - ✓ **Gemini AI による高度な脅威分析**
        - ✓ 電話番号の発信者タイプ自動判定
        - ✓ URLの安全性チェック（HTTPS、ドメイン検証）
        - ✓ メール内容の詐欺パターン検出
        - ✓ AIによる総合的なリスク評価
        - ✓ クイズ形式で楽しく学習
        - ✓ リアルタイム脅威データベース
        """)
       
        if not model or not st.session_state.api_key_validated:
            st.warning("💡 **ヒント:** サイドバーでGemini API キーを入力・検証すると、より高度なAI分析が利用できます！")
   
    # 電話番号チェック
    elif tab == "📞 電話番号チェック":
        st.header("📞 電話番号チェック")
       
        phone_number = st.text_input("電話番号を入力",placeholder="例: 090-1234-5678,03-1234-5678")
        #ここまでチェック済み
       
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button("✅ 安全サンプル", use_container_width=True):
                st.session_state.phone_number_input = "03-5555-6666"
        with col2:
            if st.button("⚠️ 注意サンプル", use_container_width=True):
                st.session_state.phone_number_input = "050-1111-2222"
        with col3:
            if st.button("🚨 危険サンプル", use_container_width=True):
                st.session_state.phone_number_input = "0120-999-999"
        with col4:
            if st.button("🌍 国際サンプル", use_container_width=True):
                st.session_state.phone_number_input = "+1-876-555-1234"
       
        st.divider()
       
        # 電話番号入力
        phone_number = st.text_input(
            "電話番号を入力", 
            value=st.session_state.phone_number_input,
            placeholder="例: 090-1234-5678, 03-1234-5678",
            key="phone_input"
        )
       
        if st.button("🔍 チェック", type="primary") and phone_number:
            with st.spinner("分析中..."):
                if model and use_ai and st.session_state.api_key_validated:
                    result = analyze_phone_with_ai(phone_number, model)
                    if result is None:
                        st.warning("AI分析に失敗しました。従来の分析を使用します。")
                        result = analyze_phone_number(phone_number)
                else:
                    result = analyze_phone_number(phone_number)
               
                display_risk_result(result)
   
    # URLチェック
    elif tab == "🔗 URLチェック":
        st.header("🔗 URLチェック")
       
        # セッション状態にURLを保存
        if 'url_input_value' not in st.session_state:
            st.session_state.url_input_value = ""
       
        # サンプルボタン
        st.subheader("📋 サンプルを試す")
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("✅ 安全なURL", use_container_width=True):
                st.session_state.url_input_value = "https://www.google.com"
        with col2:
            if st.button("⚠️ HTTP URL", use_container_width=True):
                st.session_state.url_input_value = "http://example-site.com"
        with col3:
            if st.button("🚨 危険なURL", use_container_width=True):
                st.session_state.url_input_value = "http://paypal-secure-login.com"
       
        st.divider()
       
        # URL入力
        url_input = st.text_input(
            "URLを入力", 
            value=st.session_state.url_input_value,
            placeholder="例: https://example.com",
            key="url_input"
        )
       
        if st.button("🔍 チェック", type="primary") and url_input:
            with st.spinner("分析中..."):
                if model and use_ai and st.session_state.api_key_validated:
                    result = analyze_url_with_ai(url_input, model)
                    if result is None:
                        st.warning("AI分析に失敗しました。従来の分析を使用します。")
                        result = analyze_url(url_input)
                else:
                    result = analyze_url(url_input)
               
                display_risk_result(result)
       
        st.info("""
        ### 🔍 チェックポイント
        - ✓ HTTPSが使用されているか
        - ✓ ドメイン名にスペルミスがないか
        - ✓ 短縮URLでないか
        - ✓ IPアドレスが直接使用されていないか
        """)
   
    # メールチェック
    elif tab == "📧 メールチェック":
        st.header("📧 メールチェック")
       
        # セッション状態にメール内容を保存
        if 'email_content_value' not in st.session_state:
            st.session_state.email_content_value = ""
       
        # サンプルボタン
        st.subheader("📋 サンプルを試す")
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("✅ 安全なメール", use_container_width=True):
                st.session_state.email_content_value = "【Amazon】ご注文ありがとうございます\n\nご注文いただいた商品は10月30日に発送予定です。\n配送状況はアカウントページからご確認いただけます。\n\nAmazonをご利用いただきありがとうございます。"
        with col2:
            if st.button("⚠️ 注意が必要", use_container_width=True):
                st.session_state.email_content_value = "【重要】アカウント情報の確認\n\nお客様のアカウントに不審なアクセスがありました。\n24時間以内に以下のリンクから本人確認を行ってください。\n→ https://account-verify.example.com"
        with col3:
            if st.button("🚨 危険なメール", use_container_width=True):
                st.session_state.email_content_value = "【緊急】アカウント停止通知\n\nあなたのアカウントは不審な活動により一時停止されました。\n今すぐ以下のリンクから確認しないとアカウントが削除されます。\n→ http://security-update-login.com/verify"
       
        st.divider()
       
        # メール内容入力
        email_content = st.text_area(
            "メール本文を入力", 
            value=st.session_state.email_content_value,
            placeholder="メールの内容を貼り付けてください", 
            height=200,
            key="email_input"
        )
       
        if st.button("🔍 チェック", type="primary") and email_content:
            with st.spinner("AI分析中..."):
                if model and use_ai and st.session_state.api_key_validated:
                    result = analyze_email_with_ai(email_content, model)
                    if result is None:
                        st.warning("AI分析に失敗しました。従来の分析を使用します。")
                        result = analyze_email(email_content)
                else:
                    result = analyze_email(email_content)
               
                display_risk_result(result)
       
        st.info("""
        ### 📋 チェックポイント
        - ✓ 緊急性を煽っていないか
        - ✓ 個人情報を求めていないか
        - ✓ 不自然な日本語はないか
        - ✓ リンク先が正規サイトか
        """)
   
    # 学習クイズ
    elif tab == "❓ 学習クイズ":
        st.header("❓ フィッシング詐欺クイズ")
       
        st.metric("スコア", f"{st.session_state.quiz_score} / {len(QUIZ_SAMPLES)}")
        st.progress(st.session_state.quiz_index / len(QUIZ_SAMPLES))
        st.caption(f"問題 {st.session_state.quiz_index + 1} / {len(QUIZ_SAMPLES)}")
       
        if st.session_state.quiz_index < len(QUIZ_SAMPLES):
            quiz = QUIZ_SAMPLES[st.session_state.quiz_index]
           
            st.subheader(f"✉️ 件名: {quiz['subject']}")
            st.code(quiz['content'], language=None)
           
            if not st.session_state.quiz_answered:
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("🚨 フィッシングメール", use_container_width=True):
                        if quiz['isPhishing']:
                            st.session_state.quiz_score += 1
                        st.session_state.quiz_answered = True
                        st.rerun()
                with col2:
                    if st.button("✅ 安全なメール", use_container_width=True):
                        if not quiz['isPhishing']:
                            st.session_state.quiz_score += 1
                        st.session_state.quiz_answered = True
                        st.rerun()
            else:
                if quiz['isPhishing']:
                    st.error(f"**💡 解説**\n\n{quiz['explanation']}")
                else:
                    st.success(f"**💡 解説**\n\n{quiz['explanation']}")
               
                if st.button("➡️ 次へ", type="primary"):
                    st.session_state.quiz_index += 1
                    st.session_state.quiz_answered = False
                    st.rerun()
        else:
            st.success("🎉 クイズ終了！")
            st.metric("最終スコア", f"{st.session_state.quiz_score} / {len(QUIZ_SAMPLES)}")
            st.progress(st.session_state.quiz_score / len(QUIZ_SAMPLES))
           
            if st.button("🔄 もう一度挑戦する"):
                st.session_state.quiz_index = 0
                st.session_state.quiz_score = 0
                st.session_state.quiz_answered = False
                st.rerun()
   
    # 脅威データベース
    elif tab == "💾 脅威データベース":
        st.header("💾 脅威データベース")
       
        st.subheader("🚨 既知の詐欺電話番号")
        for num in ['03-1234-5678', '0120-999-999', '050-1111-2222', '090-1234-5678']:
            st.error(f"`{num}`")
       
        st.subheader("⚠️ 疑わしいプレフィックス")
        cols = st.columns(5)
        for i, prefix in enumerate(['050', '070', '+675', '+234', '+1-876']):
            cols[i].warning(f"`{prefix}`")
       
        st.subheader("🌐 危険なドメインパターン")
        st.error("**\\*-login.com** (例: paypal-secure-login.com)")
        st.error("**\\*-verify.net** (例: amazon-verify.net)")
        st.error("**\\*-support-id.com** (例: apple-support-id.com)")
       
        st.subheader("💬 疑わしいキーワード")
        keywords = ['verify account', 'urgent action', 'suspended', 'アカウント確認', '緊急', '本人確認', 'パスワード更新', 'セキュリティ警告', '24時間以内', '今すぐ']
        st.write(" • ".join([f"`{k}`" for k in keywords]))
   
    # 使い方ガイド
    elif tab == "📖 使い方ガイド":
        st.header("📖 使い方ガイド")
       
        st.success("""
        ### 🤖 Gemini AI の使い方
        1. Google AI Studio (https://aistudio.google.com/app/apikey) でAPIキーを取得
        2. サイドバーの「Gemini API キー」欄に入力
        3. 「🔍 APIキーを検証」ボタンをクリック
        4. 「AI分析を使用」にチェックを入れる
        5. Gemini 2.0 Flash による最新AI分析が利用可能に！
       
        **使用モデル:**
        - **Gemini 2.0 Flash (実験版)**: Googleの最新AIモデル
        
        **注意事項:**
        - APIキーは必ず 'AIza' で始まります
        - APIキーが無効な場合は、Google AI Studioで新しいキーを作成してください
        - 無料枠を超えた場合は、しばらく待つか有料プランへの移行が必要です
        """)
       
        st.error("""
        ### 🚨 電話詐欺の特徴
        - 050（IP電話）や国際電話からの着信
        - 金銭や個人情報を要求する
        - 緊急性を装う（今すぐ、直ちに等）
        - 公的機関や金融機関を名乗る
        """)
       
        st.warning("""
        ### ⚠️ フィッシングメールの特徴
        - アカウント停止などの警告
        - 不自然なURL（スペルミス等）
        - 24時間以内など期限を設定
        - 個人情報の入力を要求
        """)
       
        st.success("""
        ### ✅ 対策方法
        - 知らない番号には出ない
        - URLは必ず確認してからクリック
        - 公式サイトから直接アクセス
        - 個人情報は電話で教えない
        - 怪しいと思ったら専門機関に相談
        """)
       
        st.info("""
        ### 📞 相談窓口
        - **警察相談専用電話:** #9110
        - **消費者ホットライン:** 188
        - **金融庁:** 0570-016811
        - **フィッシング対策協議会:** https://www.antiphishing.jp/
        """)
       
        st.warning("⚠️ **注意:** このアプリは補助ツールです。最終的な判断は慎重に行い、疑わしい場合は専門機関に相談してください。")
 
if __name__ == "__main__":
    main()