import streamlit as st
import requests
import json
import logging
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Algolab API configuration
ALGOLAB_HOSTNAME = "www.algolab.com.tr"  # Sadece domain
ALGOLAB_API_URL = f"https://{ALGOLAB_HOSTNAME}"  # Tam URL, sonunda slash yok

# API Endpoints - başında slash var
URL_LOGIN_USER = "/API/LoginUser"
URL_LOGIN_CONTROL = "/API/LoginUserControl"
URL_SENDORDER = "/API/SendOrder"
URL_GETEQUITYINFO = "/API/GetEquityInfo"

def encrypt(text, api_key=None):
    """AES şifreleme fonksiyonu"""
    try:
        if not text:
            return None
        
        # API key'i kontrol et
        if not api_key:
            if 'api_key' in st.session_state:
                api_key = st.session_state.api_key
                # API- prefix'ini kaldır
                if api_key.startswith("API-"):
                    api_key = api_key[4:]
            else:
                raise ValueError("API key not found")
        
        # Şifreleme
        iv = b'\0' * 16
        key = base64.b64decode(api_key.encode('utf-8'))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        bytes_data = text.encode()
        padded_bytes = pad(bytes_data, 16)
        r = cipher.encrypt(padded_bytes)
        return base64.b64encode(r).decode("utf-8")
        
    except Exception as e:
        logging.error(f"Şifreleme hatası: {str(e)}")
        raise e

def make_checker(api_key, hostname, endpoint, payload):
    """Checker oluştur"""
    try:
        # Payload'ı JSON'a çevir ve boşlukları kaldır
        if len(payload) > 0:
            body = json.dumps(payload).replace(' ', '')
        else:
            body = ""
        
        # Checker string'ini oluştur
        data = api_key + hostname + endpoint + body
        
        # SHA256 hash'i oluştur
        checker = hashlib.sha256(data.encode('utf-8')).hexdigest()
        return checker
        
    except Exception as e:
        logging.error(f"Checker oluşturma hatası: {str(e)}")
        raise e

def handle_login():
    """Handle login process"""
    try:
        # API key'i düzenle
        api_key = st.session_state.api_key
        if not api_key.startswith("API-"):
            api_key = f"API-{api_key}"
        
        # API URLs ve endpoints
        hostname = ALGOLAB_HOSTNAME  # Sadece domain
        api_url = ALGOLAB_API_URL  # Tam URL, sonunda slash yok
        
        # Login endpoint - başında slash var
        login_endpoint = URL_LOGIN_USER  # /API/LoginUser
        login_url = api_url + login_endpoint  # URL'yi doğru birleştir
        
        # Şifreleme için API Key'in "API-" olmayan halini kullan
        api_code = api_key.replace("API-", "")
        
        # Login payload
        encrypted_username = encrypt(st.session_state.tc_no, api_code)
        encrypted_password = encrypt(st.session_state.password, api_code)
        
        payload = {
            "username": encrypted_username,
            "password": encrypted_password
        }
        
        # Checker oluştur
        checker = make_checker(api_key, hostname, login_endpoint, payload)
        
        # Headers oluştur
        headers = {
            "APIKEY": api_key,  # API-XXXX formatında
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Checker": checker
        }
        
        # Debug için bilgileri yazdır
        st.write("Debug Bilgileri:")
        st.write(f"Login URL: {login_url}")
        st.write(f"Headers: {headers}")
        st.write(f"Payload: {payload}")
        st.write(f"TC No uzunluk: {len(st.session_state.tc_no)}")
        st.write(f"Şifre uzunluk: {len(st.session_state.password)}")
        st.write(f"Encrypted username length: {len(encrypted_username)}")
        st.write(f"Encrypted password length: {len(encrypted_password)}")
        st.write(f"API Key length: {len(api_key)}")
        st.write(f"Checker: {checker}")
        
        # SSL uyarılarını kapat
        requests.packages.urllib3.disable_warnings()
        
        # Login isteği
        response = requests.post(
            login_url,
            headers=headers,
            json=payload,
            verify=False  # SSL doğrulamasını devre dışı bırak
        )
        
        # Response bilgilerini yazdır
        st.write(f"Status: {response.status_code}")
        st.write(f"Response Headers: {dict(response.headers)}")
        try:
            st.write(f"Response Body: {response.json()}")
        except:
            st.write(f"Response Text: {response.text}")
        
        if response.ok:
            login_data = response.json()
            if login_data.get('success'):
                # Token al
                token = login_data['content']['token']
                
                # SMS kodu iste
                sms_code = st.text_input("📱 Lütfen telefonunuza gelen SMS kodunu girin:", key="sms_code")
                
                if sms_code:
                    # SMS doğrulama
                    encrypted_token = encrypt(token, api_code)
                    encrypted_sms = encrypt(sms_code, api_code)
                    
                    verify_payload = {
                        'token': encrypted_token,
                        'password': encrypted_sms
                    }
                    
                    verify_url = f"{api_url}/API/LoginUserControl"
                    verify_response = requests.post(
                        verify_url,
                        headers=headers,
                        json=verify_payload,
                        verify=False
                    )
                    
                    # Response bilgilerini yazdır
                    st.write(f"Verify Status: {verify_response.status_code}")
                    st.write(f"Verify Response Headers: {dict(verify_response.headers)}")
                    try:
                        st.write(f"Verify Response Body: {verify_response.json()}")
                    except:
                        st.write(f"Verify Response Text: {verify_response.text}")
                    
                    if verify_response.ok:
                        verify_data = verify_response.json()
                        if verify_data.get('success'):
                            return verify_data
                        else:
                            raise Exception(f"SMS doğrulama hatası: {verify_data.get('message')}")
                    else:
                        raise Exception(f"SMS doğrulama hatası: HTTP {verify_response.status_code}")
            else:
                raise Exception(f"Login başarısız: {login_data.get('message')}")
        else:
            error_msg = f"Login başarısız: HTTP {response.status_code}"
            if response.text:
                error_msg += f"\nYanıt: {response.text}"
            raise Exception(error_msg)
            
    except Exception as e:
        if isinstance(e, requests.exceptions.RequestException):
            error_msg = f"API hatası: {str(e)}"
            if hasattr(e, 'response') and e.response is not None and e.response.text:
                error_msg += f"\nYanıt: {e.response.text}"
        else:
            error_msg = f"Hata: {str(e)}"
        logging.error(error_msg)
        raise Exception(error_msg)

def send_order_to_algolab(order_data):
    """
    Algolab API'sine emir gönderen fonksiyon
    """
    try:
        # API bilgilerinin ayarlanıp ayarlanmadığını kontrol et
        if not st.session_state.is_configured:
            raise Exception("Lütfen önce API bilgilerinizi ayarlayın!")
        
        # API key'i düzenle
        api_key = st.session_state.api_key
        if not api_key.startswith("API-"):
            api_key = f"API-{api_key}"
        
        # API URLs ve endpoints
        hostname = ALGOLAB_HOSTNAME  # Sadece domain
        api_url = ALGOLAB_API_URL  # Tam URL, sonunda slash yok
        
        # Login endpoint - başında slash var
        login_endpoint = URL_LOGIN_USER  # /API/LoginUser
        login_url = api_url + login_endpoint  # URL'yi doğru birleştir
        
        # Şifreleme için API Key'in "API-" olmayan halini kullan
        api_code = api_key.replace("API-", "")
        
        # Login payload
        encrypted_username = encrypt(st.session_state.tc_no, api_code)
        encrypted_password = encrypt(st.session_state.password, api_code)
        
        payload = {
            "username": encrypted_username,
            "password": encrypted_password
        }
        
        # Checker oluştur
        checker = make_checker(api_key, hostname, login_endpoint, payload)
        
        # Headers oluştur
        headers = {
            "APIKEY": api_key,  # API-XXXX formatında
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Checker": checker
        }
        
        # Debug için bilgileri yazdır
        st.write("Debug Bilgileri:")
        st.write(f"Login URL: {login_url}")
        st.write(f"Headers: {headers}")
        st.write(f"Payload: {payload}")
        st.write(f"TC No uzunluk: {len(st.session_state.tc_no)}")
        st.write(f"Şifre uzunluk: {len(st.session_state.password)}")
        st.write(f"Encrypted username length: {len(encrypted_username)}")
        st.write(f"Encrypted password length: {len(encrypted_password)}")
        st.write(f"API Key length: {len(api_key)}")
        st.write(f"Checker: {checker}")
        
        # SSL uyarılarını kapat
        requests.packages.urllib3.disable_warnings()
        
        # Login isteği
        response = requests.post(
            login_url,
            headers=headers,
            json=payload,
            verify=False  # SSL doğrulamasını devre dışı bırak
        )
        
        # Response bilgilerini yazdır
        st.write(f"Status: {response.status_code}")
        st.write(f"Response Headers: {dict(response.headers)}")
        try:
            st.write(f"Response Body: {response.json()}")
        except:
            st.write(f"Response Text: {response.text}")
        
        if response.ok:
            login_data = response.json()
            if login_data.get('success'):
                # Token al
                token = login_data['content']['token']
                
                # SMS kodu iste
                sms_code = st.text_input("📱 Lütfen telefonunuza gelen SMS kodunu girin:", key="sms_code")
                
                if sms_code:
                    # SMS doğrulama
                    encrypted_token = encrypt(token, api_code)
                    encrypted_sms = encrypt(sms_code, api_code)
                    
                    verify_payload = {
                        'token': encrypted_token,
                        'password': encrypted_sms
                    }
                    
                    verify_url = f"{api_url}/API/LoginUserControl"
                    verify_response = requests.post(
                        verify_url,
                        headers=headers,
                        json=verify_payload,
                        verify=False
                    )
                    
                    # Response bilgilerini yazdır
                    st.write(f"Verify Status: {verify_response.status_code}")
                    st.write(f"Verify Response Headers: {dict(verify_response.headers)}")
                    try:
                        st.write(f"Verify Response Body: {verify_response.json()}")
                    except:
                        st.write(f"Verify Response Text: {verify_response.text}")
                    
                    if verify_response.ok:
                        verify_data = verify_response.json()
                        if verify_data.get('success'):
                            # Emir verisi hazırla
                            order_payload = {
                                'symbol': order_data['symbol'],
                                'price': float(order_data['price']),
                                'lot': int(order_data['quantity']),
                                'side': 1 if order_data['side'].upper() == 'BUY' else 2,
                                'ordertype': 1 if order_data['type'].upper() == 'MARKET' else 0,
                                'validity': 0,
                                'market': 1
                            }
                            
                            order_url = f"{api_url}/API/SendOrder"
                            logging.info(f"Order URL: {order_url}")
                            
                            # Emir gönder
                            response = requests.post(
                                order_url,
                                headers=headers,
                                json=order_payload,
                                verify=False
                            )
                            
                            logging.info(f"Emir yanıtı: Status={response.status_code}")
                            if response.text:
                                logging.info(f"Emir yanıt içeriği: {response.text}")
                            
                            if response.ok:
                                return response.json()
                            else:
                                error_msg = f"Emir hatası: HTTP {response.status_code}"
                                if response.text:
                                    error_msg += f"\nYanıt: {response.text}"
                                raise Exception(error_msg)
                        else:
                            raise Exception(f"SMS doğrulama hatası: {verify_data.get('message')}")
                    else:
                        raise Exception(f"SMS doğrulama hatası: HTTP {verify_response.status_code}")
            else:
                raise Exception(f"Login başarısız: {login_data.get('message')}")
        else:
            error_msg = f"Login başarısız: HTTP {response.status_code}"
            if response.text:
                error_msg += f"\nYanıt: {response.text}"
            raise Exception(error_msg)
            
    except Exception as e:
        if isinstance(e, requests.exceptions.RequestException):
            error_msg = f"API hatası: {str(e)}"
            if hasattr(e, 'response') and e.response is not None and e.response.text:
                error_msg += f"\nYanıt: {e.response.text}"
        else:
            error_msg = f"Hata: {str(e)}"
        logging.error(error_msg)
        raise Exception(error_msg)

def get_portfolio_summary():
    """
    Algolab API'sinden portföy özetini getiren fonksiyon
    """
    try:
        # API bilgilerinin ayarlanıp ayarlanmadığını kontrol et
        if not st.session_state.is_configured:
            raise Exception("Lütfen önce API bilgilerinizi ayarlayın!")
        
        # API key'i düzenle
        api_key = st.session_state.api_key
        if not api_key.startswith("API-"):
            api_key = f"API-{api_key}"
        
        # API URLs ve endpoints
        hostname = ALGOLAB_HOSTNAME  # Sadece domain
        api_url = ALGOLAB_API_URL  # Tam URL, sonunda slash yok
        
        # Login endpoint - başında slash var
        login_endpoint = URL_LOGIN_USER  # /API/LoginUser
        login_url = api_url + login_endpoint  # URL'yi doğru birleştir
        
        # Şifreleme için API Key'in "API-" olmayan halini kullan
        api_code = api_key.replace("API-", "")
        
        # Login payload
        encrypted_username = encrypt(st.session_state.tc_no, api_code)
        encrypted_password = encrypt(st.session_state.password, api_code)
        
        payload = {
            "username": encrypted_username,
            "password": encrypted_password
        }
        
        # Checker oluştur
        checker = make_checker(api_key, hostname, login_endpoint, payload)
        
        # Headers oluştur
        headers = {
            "APIKEY": api_key,  # API-XXXX formatında
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Checker": checker
        }
        
        # Debug için bilgileri yazdır
        st.write("Debug Bilgileri:")
        st.write(f"Login URL: {login_url}")
        st.write(f"Headers: {headers}")
        st.write(f"Payload: {payload}")
        st.write(f"TC No uzunluk: {len(st.session_state.tc_no)}")
        st.write(f"Şifre uzunluk: {len(st.session_state.password)}")
        st.write(f"Encrypted username length: {len(encrypted_username)}")
        st.write(f"Encrypted password length: {len(encrypted_password)}")
        st.write(f"API Key length: {len(api_key)}")
        st.write(f"Checker: {checker}")
        
        # SSL uyarılarını kapat
        requests.packages.urllib3.disable_warnings()
        
        # Login isteği
        response = requests.post(
            login_url,
            headers=headers,
            json=payload,
            verify=False  # SSL doğrulamasını devre dışı bırak
        )
        
        # Response bilgilerini yazdır
        st.write(f"Status: {response.status_code}")
        st.write(f"Response Headers: {dict(response.headers)}")
        try:
            st.write(f"Response Body: {response.json()}")
        except:
            st.write(f"Response Text: {response.text}")
        
        if response.ok:
            login_data = response.json()
            if login_data.get('success'):
                # Token al
                token = login_data['content']['token']
                
                # SMS kodu iste
                sms_code = st.text_input("📱 Lütfen telefonunuza gelen SMS kodunu girin:", key="portfolio_sms_code")
                
                if sms_code:
                    # SMS doğrulama
                    encrypted_token = encrypt(token, api_code)
                    encrypted_sms = encrypt(sms_code, api_code)
                    
                    verify_payload = {
                        'token': encrypted_token,
                        'password': encrypted_sms
                    }
                    
                    verify_url = f"{api_url}/API/LoginUserControl"
                    verify_response = requests.post(
                        verify_url,
                        headers=headers,
                        json=verify_payload,
                        verify=False
                    )
                    
                    # Response bilgilerini yazdır
                    st.write(f"Verify Status: {verify_response.status_code}")
                    st.write(f"Verify Response Headers: {dict(verify_response.headers)}")
                    try:
                        st.write(f"Verify Response Body: {verify_response.json()}")
                    except:
                        st.write(f"Verify Response Text: {verify_response.text}")
                    
                    if verify_response.ok:
                        verify_data = verify_response.json()
                        if verify_data.get('success'):
                            # Portföy bilgisini al
                            portfolio_url = f"{api_url}/API/GetEquityInfo"
                            portfolio_response = requests.get(
                                portfolio_url,
                                headers=headers,
                                verify=False
                            )
                            
                            # Response bilgilerini yazdır
                            st.write(f"Portfolio Status: {portfolio_response.status_code}")
                            st.write(f"Portfolio Response Headers: {dict(portfolio_response.headers)}")
                            try:
                                st.write(f"Portfolio Response Body: {portfolio_response.json()}")
                            except:
                                st.write(f"Portfolio Response Text: {portfolio_response.text}")
                            
                            if portfolio_response.ok:
                                portfolio_data = portfolio_response.json()
                                if portfolio_data.get('success'):
                                    return portfolio_data['content']
                                else:
                                    raise Exception(f"Portföy bilgisi alınamadı: {portfolio_data.get('message')}")
                            else:
                                raise Exception(f"Portföy bilgisi alınamadı: HTTP {portfolio_response.status_code}")
                        else:
                            raise Exception(f"SMS doğrulama hatası: {verify_data.get('message')}")
                    else:
                        raise Exception(f"SMS doğrulama hatası: HTTP {verify_response.status_code}")
            else:
                raise Exception(f"Login başarısız: {login_data.get('message')}")
        else:
            error_msg = f"Login başarısız: HTTP {response.status_code}"
            if response.text:
                error_msg += f"\nYanıt: {response.text}"
            raise Exception(error_msg)
            
    except Exception as e:
        if isinstance(e, requests.exceptions.RequestException):
            error_msg = f"API hatası: {str(e)}"
            if hasattr(e, 'response') and e.response is not None and e.response.text:
                error_msg += f"\nYanıt: {e.response.text}"
        else:
            error_msg = f"Hata: {str(e)}"
        logging.error(error_msg)
        raise Exception(error_msg)

def log_order(order_data, result):
    """
    Emirleri logla
    """
    with open("orders.log", "a") as f:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "order": order_data,
            "response": result
        }
        f.write(json.dumps(log_entry) + "\n")

def main():
    st.title("🤖 TradingView - Algolab Entegrasyonu")
    
    # Initialize session state
    if 'api_key' not in st.session_state:
        st.session_state.api_key = ''
    if 'tc_no' not in st.session_state:
        st.session_state.tc_no = ''
    if 'password' not in st.session_state:
        st.session_state.password = ''
    if 'is_configured' not in st.session_state:
        st.session_state.is_configured = False
    
    # Sidebar for API configuration
    st.sidebar.title("⚙️ API Ayarları")
    
    # API configuration form
    with st.sidebar.form("api_settings"):
        st.markdown("""
        ### API Key
        Algolab'dan aldığınız API anahtarı. 'API-' öneki otomatik olarak eklenecektir.
        Örnek format: Eğer API Key'iniz 'API-ABC123' ise, sadece 'ABC123' girin.
        """)
        api_key = st.text_input("API Key:", type="password")
        
        st.markdown("""
        ### TC Kimlik No
        Denizbank/Algolab hesabınıza bağlı TC Kimlik numaranız.
        """)
        tc_no = st.text_input("TC Kimlik No:")
        
        st.markdown("""
        ### Şifre
        Denizbank/Algolab hesap şifreniz.
        """)
        password = st.text_input("Şifre:", type="password")
        
        # Test connection button
        if st.form_submit_button("🔄 Bağlantıyı Test Et"):
            try:
                # API key'i düzenle
                if not api_key.startswith("API-"):
                    api_key = f"API-{api_key}"
                
                # API URLs ve endpoints
                hostname = ALGOLAB_HOSTNAME  # Sadece domain
                api_url = ALGOLAB_API_URL  # Tam URL, sonunda slash yok
                
                # Login endpoint - başında slash var
                login_endpoint = URL_LOGIN_USER  # /API/LoginUser
                login_url = api_url + login_endpoint  # URL'yi doğru birleştir
                
                # Şifreleme için API Key'in "API-" olmayan halini kullan
                api_code = api_key.replace("API-", "")
                
                # Login payload
                encrypted_username = encrypt(tc_no, api_code)
                encrypted_password = encrypt(password, api_code)
                
                payload = {
                    "username": encrypted_username,
                    "password": encrypted_password
                }
                
                # Checker oluştur
                checker = make_checker(api_key, hostname, login_endpoint, payload)
                
                # Headers oluştur
                headers = {
                    "APIKEY": api_key,  # API-XXXX formatında
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Checker": checker
                }
                
                # Debug için bilgileri yazdır
                st.write("Debug Bilgileri:")
                st.write(f"Login URL: {login_url}")
                st.write(f"Headers: {headers}")
                st.write(f"Payload: {payload}")
                st.write(f"TC No uzunluk: {len(tc_no)}")
                st.write(f"Şifre uzunluk: {len(password)}")
                st.write(f"Encrypted username length: {len(encrypted_username)}")
                st.write(f"Encrypted password length: {len(encrypted_password)}")
                st.write(f"API Key length: {len(api_key)}")
                st.write(f"Checker: {checker}")
                
                # SSL uyarılarını kapat
                requests.packages.urllib3.disable_warnings()
                
                # Login isteği
                response = requests.post(
                    login_url,
                    headers=headers,
                    json=payload,
                    verify=False  # SSL doğrulamasını devre dışı bırak
                )
                
                # Response bilgilerini yazdır
                st.write(f"Status: {response.status_code}")
                st.write(f"Response Headers: {dict(response.headers)}")
                try:
                    st.write(f"Response Body: {response.json()}")
                except:
                    st.write(f"Response Text: {response.text}")
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        st.success("✅ API bağlantısı başarılı!")
                        # Token'ı kaydet
                        token = data['content']['token']
                        st.session_state.token = token
                        
                        # SMS kodu için input
                        sms_code = st.text_input("📱 SMS Kodu:", type="password")
                        
                        if sms_code:
                            # SMS doğrulama
                            encrypted_token = encrypt(token, api_code)
                            encrypted_sms = encrypt(sms_code, api_code)
                            
                            verify_payload = {
                                'token': encrypted_token,
                                'password': encrypted_sms
                            }
                            
                            verify_url = f"{api_url}/API/LoginUserControl"
                            verify_response = requests.post(
                                verify_url,
                                headers=headers,
                                json=verify_payload,
                                verify=False
                            )
                            
                            # Response bilgilerini yazdır
                            st.write(f"Verify Status: {verify_response.status_code}")
                            st.write(f"Verify Response Headers: {dict(verify_response.headers)}")
                            try:
                                st.write(f"Verify Response Body: {verify_response.json()}")
                            except:
                                st.write(f"Verify Response Text: {verify_response.text}")
                            
                            if verify_response.status_code == 200:
                                verify_data = verify_response.json()
                                if verify_data.get('success'):
                                    st.success("✅ SMS doğrulama başarılı!")
                                    # Session state'i güncelle
                                    st.session_state.api_key = api_key
                                    st.session_state.tc_no = tc_no
                                    st.session_state.password = password
                                    st.session_state.is_configured = True
                                else:
                                    st.error(f"❌ SMS doğrulama hatası: {verify_data.get('message')}")
                            else:
                                st.error(f"❌ SMS doğrulama hatası: HTTP {verify_response.status_code}")
                    else:
                        st.error(f"❌ Login başarısız: {data.get('message')}")
                else:
                    st.error(f"❌ API bağlantısı başarısız!")
                
            except Exception as e:
                st.error(f"❌ Hata: {str(e)}")
    
    # Show configuration status
    if st.session_state.is_configured:
        st.sidebar.success("✅ API Bağlantısı: Ayarlandı")
        
        # Portföy özeti butonu
        if st.sidebar.button("📊 Portföy Özetini Göster"):
            try:
                portfolio = get_portfolio_summary()
                if portfolio:
                    st.success("✅ API bağlantısı başarılı!")
                    st.subheader("📊 Portföy Özeti")
                    
                    # Portföy verilerini göster
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Toplam Varlık", f"₺{portfolio.get('total_assets', 0):,.2f}")
                        st.metric("Nakit", f"₺{portfolio.get('cash', 0):,.2f}")
                    with col2:
                        st.metric("Kar/Zarar", f"₺{portfolio.get('pl', 0):,.2f}")
                        st.metric("Açık Pozisyonlar", portfolio.get('open_positions', 0))
                    
            except Exception as e:
                st.error(f"❌ {str(e)}")
    else:
        st.sidebar.warning("⚠️ API Bağlantısı: Ayarlanmadı")
    
    # API durumunu kontrol et
    if not st.session_state.is_configured:
        st.warning("⚠️ Lütfen önce sol menüden API bilgilerinizi ayarlayın!")
        st.stop()
    
    # Manuel emir girişi
    st.header("📊 Manuel Emir Girişi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        symbol = st.text_input("Sembol", "GARAN")
        price = st.number_input("Fiyat", min_value=0.0, value=0.0, step=0.01)
        
    with col2:
        side = st.selectbox("İşlem Yönü", ["BUY", "SELL"])
        quantity = st.number_input("Lot", min_value=1, value=1, step=1)
    
    order_type = st.selectbox("Emir Tipi", ["LIMIT", "MARKET"])
    
    if st.button("💫 Emir Gönder"):
        with st.spinner("Emir gönderiliyor..."):
            try:
                order_data = {
                    "symbol": symbol,
                    "side": side,
                    "price": price,
                    "quantity": quantity,
                    "type": order_type
                }
                
                result = send_order_to_algolab(order_data)
                st.success(f"✅ Emir başarıyla gönderildi!")
                st.json(result)
                log_order(order_data, result)
                    
            except Exception as e:
                st.error(f"❌ Hata: {str(e)}")
    
    # Son emirleri göster
    st.header("📜 Son Emirler")
    try:
        with open("orders.log", "r") as f:
            orders = [json.loads(line) for line in f.readlines()]
            for order in reversed(orders[-5:]):  # Son 5 emri göster
                with st.expander(f"🕒 {order['timestamp']} - {order['order']['symbol']}"):
                    st.json(order)
    except FileNotFoundError:
        st.info("📝 Henüz emir kaydı bulunmuyor")

if __name__ == '__main__':
    main()
