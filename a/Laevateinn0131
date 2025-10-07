import streamlit as st
import google.generativeai as genai
import json
import re

# ページ設定
st.set_page_config(
    page_title="フィッシング詐欺検知アプリ",
    page_icon="🛡️",
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
    }
    .risk-medium {
        background-color: #fef3c7;
        border-left: 5px solid #f59e0b;
        padding: 1rem;
        border-radius: 5px;
    }
    .risk-low {
        background-color: #d1fae5;
        border-left: 5px solid #10b981;
        padding: 1rem;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# ヘッダー
st.markdown("""
<div class="main-header">
    <h1>🛡️ フィッシング詐欺検知アプリ</h1>
    <p>Gemini AIで怪しいURLやメールを分析</p>
</div>
""", unsafe_allow_html=True)

# サイドバー設定
with st.sidebar:
    st.header("⚙️ 設定")
    api_key = st.text_input(
        "Gemini APIキー",
        type="password",
        help="Google AI StudioでAPIキーを取得: https://makersuite.google.com/app/apikey"
    )
    
    st.markdown("---")
    
    analysis_type = st.radio(
        "分析タイプ",
        ["URL", "メール内容"],
        index=0
    )
    
    st.markdown("---")
    
    st.markdown("""
    ### 📝 使い方
    1. APIキーを入力
    2. 分析タイプを選択
    3. 内容を入力して分析
    
    ### ⚠️ 注意
    - APIキーは安全に管理してください
    - 個人情報は入力しないでください
    """)

# メインコンテンツ
col1, col2 = st.columns([2, 1])

with col1:
    st.header("🔍 分析対象")
    
    if analysis_type == "URL":
        input_text = st.text_area(
            "チェックするURLを入力",
            placeholder="https://example.com",
            height=100
        )
    else:
        input_text = st.text_area(
            "メール本文を入力",
            placeholder="メールの内容を貼り付けてください",
            height=300
        )
    
    analyze_button = st.button("🔎 分析を開始", type="primary", use_container_width=True)

with col2:
    st.header("💡 ヒント")
    if analysis_type == "URL":
        st.info("""
        **チェックポイント:**
        - スペルミスがないか
        - HTTPSかHTTPか
        - ドメインが本物か
        - 短縮URLでないか
        """)
    else:
        st.info("""
        **チェックポイント:**
        - 緊急性を煽っていないか
        - 個人情報を求めていないか
        - 不自然な日本語はないか
        - リンク先が正規サイトか
        """)

# 分析処理
if analyze_button:
    if not api_key:
        st.error("❌ APIキーを入力してください")
    elif not input_text:
        st.error("❌ 分析する内容を入力してください")
    else:
        with st.spinner("🤖 AIが分析中..."):
            try:
                # Gemini API設定
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel('gemini-1.5-flash')
                
                # プロンプト作成
                if analysis_type == "URL":
                    prompt = f"""以下のURLがフィッシング詐欺サイトである可能性を分析してください。
URL: {input_text}

以下の形式でJSON形式で回答してください：
{{
  "risk_level": "high/medium/low",
  "risk_score": 0-100の数値,
  "is_suspicious": true/false,
  "indicators": ["疑わしい点のリスト"],
  "recommendation": "ユーザーへの推奨アクション",
  "summary": "分析結果の簡潔な要約"
}}"""
                else:
                    prompt = f"""以下のメール内容がフィッシング詐欺である可能性を分析してください。
メール内容:
{input_text}

以下の形式でJSON形式で回答してください：
{{
  "risk_level": "high/medium/low",
  "risk_score": 0-100の数値,
  "is_suspicious": true/false,
  "indicators": ["疑わしい点のリスト"],
  "recommendation": "ユーザーへの推奨アクション",
  "summary": "分析結果の簡潔な要約"
}}"""
                
                # API呼び出し
                response = model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.2,
                        max_output_tokens=1000,
                    )
                )
                
                # JSONを抽出
                response_text = response.text
                json_match = re.search(r'\{[\s\S]*\}', response_text)
                
                if json_match:
                    result = json.loads(json_match.group())
                    
                    # 結果表示
                    st.markdown("---")
                    st.header("📊 分析結果")
                    
                    # リスクレベル表示
                    risk_level = result['risk_level']
                    risk_score = result['risk_score']
                    
                    if risk_level == 'high':
                        st.markdown(f'<div class="risk-high"><h2>⚠️ 高リスク ({risk_score}/100)</h2><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                    elif risk_level == 'medium':
                        st.markdown(f'<div class="risk-medium"><h2>⚡ 中リスク ({risk_score}/100)</h2><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="risk-low"><h2>✅ 低リスク ({risk_score}/100)</h2><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                    
                    # プログレスバー
                    st.progress(risk_score / 100)
                    
                    # 詳細情報
                    col_a, col_b = st.columns(2)
                    
                    with col_a:
                        st.subheader("🔍 検出された疑わしい点")
                        for i, indicator in enumerate(result['indicators'], 1):
                            st.markdown(f"{i}. {indicator}")
                    
                    with col_b:
                        st.subheader("💡 推奨アクション")
                        st.info(result['recommendation'])
                    
                    # 判定結果
                    if result['is_suspicious']:
                        st.error("🚨 このコンテンツは疑わしいと判定されました。注意してください。")
                    else:
                        st.success("✅ このコンテンツは安全である可能性が高いです。")
                    
                else:
                    st.error("❌ 分析結果の解析に失敗しました")
                    
            except Exception as e:
                st.error(f"❌ エラーが発生しました: {str(e)}")

# フッター
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem;">
    <p>⚠️ このツールは補助的なものです。最終的な判断は慎重に行ってください。</p>
    <p>Powered by Google Gemini AI</p>
</div>
""", unsafe_allow_html=True)