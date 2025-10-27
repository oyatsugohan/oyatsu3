import streamlit as st
import re
from urllib.parse import urlparse
 
# ページ設定
st.set_page_config(
  page_title="詐欺対策総合アプリ",
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
 
# 電話番号分析関数
def analyze_phone_number(number):
  normalized = re.sub(r'[-\s()]+', '', number)
  risk_level = '安全'
  risk_score = 10
  warnings = []
  details = []
  caller_type = {'type': '不明', 'category': 'その他', 'confidence': '低'}
 
   # 緊急番号チェック
  if normalized in ['110', '119', '118']:
      caller_type = {'type': '緊急通報番号', 'category': '公的機関', 'confidence': '確実'}
      risk_level = '緊急'
      details.append('✅ 緊急通報番号です')
   # 公的機関パターン
  elif normalized.startswith('033581') or normalized.startswith('035253'):
      caller_type = {'type': '公的機関', 'category': '公的機関', 'confidence': '高'}
      details.append('🏛️ 官公庁の番号パターン')
   # フリーダイヤル
  elif normalized.startswith('0120') or normalized.startswith('0800'):
      caller_type = {'type': '企業カスタマーサポート', 'category': '一般企業', 'confidence': '中'}
      details.append('📞 フリーダイヤル（通話無料）')
   # IP電話（要注意）
  elif normalized.startswith('050'):
      caller_type = {'type': 'IP電話利用者', 'category': '不明', 'confidence': '低'}
      warnings.append('⚠️ IP電話は匿名性が高く、詐欺に悪用されやすい')
      risk_level = '注意'
      risk_score = 60
   # 携帯電話
  elif normalized.startswith(('090', '080', '070')):
      caller_type = {'type': '個人携帯電話', 'category': '個人', 'confidence': '高'}
      details.append('📱 個人契約の携帯電話')
   # 国際電話
  elif number.startswith('+') or normalized.startswith('010'):
      caller_type = {'type': '国際電話', 'category': '国際', 'confidence': '確実'}
      warnings.append('🌍 国際電話 - 身に覚えがない場合は応答しない')
      risk_level = '注意'
      risk_score = 70
   # 固定電話
  elif normalized.startswith('0'):
      caller_type = {'type': '固定電話', 'category': '企業または個人', 'confidence': '中'}
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
      'caller_type': caller_type
   }
 
# URL分析関数
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
      'details': details
   }
 
# メール分析関数
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
      'details': details
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
  
  st.markdown(f"### リスク判定: :{color}[{result['risk_level']}]")
  st.metric("リスクスコア", f"{result['risk_score']}/100")
  
   # 発信者タイプ（電話番号の場合）
  if 'caller_type' in result:
      st.info(f"""
      **📞 発信者タイプ**    
    　- **種別:** {result['caller_type']['type']}
      - **カテゴリ:** {result['caller_type']['category']}
      - **信頼度:** {result['caller_type']['confidence']}
      """)
  
   # 警告
  if result['warnings']:
      st.warning("**⚠️ 警告**\n\n" + "\n\n".join(result['warnings']))
  
   # 詳細情報
  if result['details']:
      with st.expander("📋 詳細情報"):
          for detail in result['details']:
               st.write(detail)
 
# メインアプリ
def main():
  st.title("🛡️ 詐欺対策総合アプリ")
  st.markdown("電話・メール・URLの安全性を多角的にチェック")
  
   # サイドバーでタブ選択
  tab = st.sidebar.radio(
      "メニュー",
      ["🏠 ホーム", "📞 電話番号チェック", "🔗 URLチェック", "📧 メールチェック", "❓ 学習クイズ", "💾 脅威データベース", "📖 使い方ガイド"]
   )
  
   # ホーム画面
  if tab == "🏠 ホーム":
      col1, col2 = st.columns(2)
      
      with col1:
          st.info("""
          ### 📞 電話番号チェック
          詐欺電話の可能性を分析
          """)
          
          st.success("""
          ### 🔗 URLチェック
          フィッシングサイトを検出
          """)
      
      with col2:
          st.warning("""
          ### 📧 メールチェック
          詐欺メールの特徴を分析
          """)
          
          st.error("""
          ### ❓ 学習クイズ
          詐欺を見抜く力をつける
          """)
      
      st.info("""
      ### 主な機能
      - ✓ 電話番号の発信者タイプ自動判定（個人/企業/公的機関など）
      - ✓ URLの安全性チェック（HTTPS、ドメイン検証）
      - ✓ メール内容の詐欺パターン検出
      - ✓ クイズ形式で楽しく学習
      - ✓ リアルタイム脅威データベース
      """)
  
   # 電話番号チェック
  elif tab == "📞 電話番号チェック":
      st.header("📞 電話番号チェック")
      
      phone_number = st.text_input("電話番号を入力", placeholder="例: 090-1234-5678, 03-1234-5678")
      
      col1, col2, col3, col4 = st.columns(4)
      with col1:
          if st.button("✅ 安全サンプル"):
               phone_number = "03-5555-6666"
      with col2:
          if st.button("⚠️ 注意サンプル"):
               phone_number = "050-1111-2222"
      with col3:
          if st.button("🚨 危険サンプル"):
               phone_number = "090-1234-5678"
      with col4:
          if st.button("🌍 国際サンプル"):
               phone_number = "+1-876-555-1234"
      
      if st.button("🔍 チェック", type="primary") and phone_number:
          result = analyze_phone_number(phone_number)
          display_risk_result(result)
  
   # URLチェック
  elif tab == "🔗 URLチェック":
      st.header("🔗 URLチェック")
      
      url_input = st.text_input("URLを入力", placeholder="例: https://example.com")
      
      if st.button("🔍 チェック", type="primary") and url_input:
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
      
      email_content = st.text_area("メール本文を入力", placeholder="メールの内容を貼り付けてください", height=200)
      
      if st.button("🔍 チェック", type="primary") and email_content:
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