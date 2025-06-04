#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive Honeypot Data Analyzer
مشروع محلل بيانات مصيدة التسلل التفاعلي

الجزء الأول: مصيدة التسلل (Honeypot)
"""

import socket
import threading
import datetime
import json
import time
import os
from typing import Dict, Any

class TelnetHoneypot:
    """
    مصيدة تسلل تحاكي خدمة Telnet لاصطياد المهاجمين
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 2323, log_file: str = "honeypot_logs.json"):
        self.host = host
        self.port = port
        self.log_file = log_file
        self.is_running = False
        self.connection_count = 0
        
        # رسائل المحاكاة
        self.fake_banner = "Ubuntu 18.04.3 LTS\r\nlogin: "
        self.fake_responses = {
            "login_success": "Last login: Mon Jan 20 10:30:45 2025 from 192.168.1.100\r\n$ ",
            "login_failed": "Login incorrect\r\nlogin: ",
            "command_not_found": "bash: {}: command not found\r\n$ ",
            "fake_ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n$ ",
            "fake_whoami": "root\r\n$ ",
            "fake_pwd": "/root\r\n$ "
        }
        
        # إنشاء ملف السجل إذا لم يكن موجوداً
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', encoding='utf-8') as f:
                pass
    
    def log_interaction(self, client_ip: str, client_port: int, data: Dict[str, Any]):
        """
        تسجيل التفاعل مع المهاجم في ملف السجل
        """
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "client_ip": client_ip,
            "client_port": client_port,
            "session_id": data.get("session_id"),
            "interaction_type": data.get("type"),
            "content": data.get("content", ""),
            "response_sent": data.get("response", "")
        }
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            print(f"[LOG] {client_ip}:{client_port} - {data.get('type', 'unknown')}")
        except Exception as e:
            print(f"[ERROR] فشل في تسجيل السجل: {e}")
    
    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        """
        التعامل مع اتصال المهاجم
        """
        client_ip, client_port = client_address
        session_id = f"session_{int(time.time())}_{client_port}"
        
        print(f"[NEW CONNECTION] {client_ip}:{client_port}")
        
        # تسجيل الاتصال الجديد
        self.log_interaction(client_ip, client_port, {
            "session_id": session_id,
            "type": "connection_established",
            "content": "New connection established"
        })
        
        try:
            # إرسال شعار مزيف
            client_socket.send(self.fake_banner.encode('utf-8'))
            
            username = None
            login_attempts = 0
            max_login_attempts = 3
            logged_in = False
            
            while True:
                try:
                    # استقبال البيانات
                    data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    if not data:
                        break
                    
                    print(f"[DATA] {client_ip}: {repr(data)}")
                    
                    # إذا لم يسجل الدخول بعد
                    if not logged_in:
                        if username is None:
                            # أول إدخال هو اسم المستخدم
                            username = data
                            self.log_interaction(client_ip, client_port, {
                                "session_id": session_id,
                                "type": "username_attempt",
                                "content": username
                            })
                            client_socket.send(b"Password: ")
                        else:
                            # ثاني إدخال هو كلمة المرور
                            password = data
                            login_attempts += 1
                            
                            self.log_interaction(client_ip, client_port, {
                                "session_id": session_id,
                                "type": "password_attempt",
                                "content": f"{username}:{password}"
                            })
                            
                            # محاكاة نجح الدخول أحياناً لجذب المهاجم
                            if login_attempts <= max_login_attempts and (
                                username.lower() in ['admin', 'root', 'user'] or 
                                password.lower() in ['123456', 'password', 'admin']
                            ):
                                logged_in = True
                                response = self.fake_responses["login_success"]
                                client_socket.send(response.encode('utf-8'))
                                
                                self.log_interaction(client_ip, client_port, {
                                    "session_id": session_id,
                                    "type": "login_success",
                                    "content": f"{username}:{password}",
                                    "response": "Login successful"
                                })
                            else:
                                if login_attempts >= max_login_attempts:
                                    client_socket.send(b"Too many login attempts. Connection closed.\r\n")
                                    break
                                else:
                                    response = self.fake_responses["login_failed"]
                                    client_socket.send(response.encode('utf-8'))
                                    username = None  # إعادة تعيين لمحاولة جديدة
                    
                    else:
                        # بعد تسجيل الدخول - محاكاة الأوامر
                        command = data.lower().strip()
                        
                        self.log_interaction(client_ip, client_port, {
                            "session_id": session_id,
                            "type": "command_execution",
                            "content": command
                        })
                        
                        # الاستجابة للأوامر الشائعة
                        if command == "ls" or command == "ls -la":
                            response = self.fake_responses["fake_ls"]
                        elif command == "whoami":
                            response = self.fake_responses["fake_whoami"]
                        elif command == "pwd":
                            response = self.fake_responses["fake_pwd"]
                        elif command in ["exit", "quit", "logout"]:
                            client_socket.send(b"Goodbye!\r\n")
                            break
                        elif command.startswith("cat ") or command.startswith("vi ") or command.startswith("nano "):
                            response = f"bash: {command.split()[0]}: Permission denied\r\n$ "
                        elif command == "ps" or command == "ps aux":
                            response = "  PID TTY          TIME CMD\r\n 1234 pts/0    00:00:01 bash\r\n$ "
                        elif command.startswith("wget ") or command.startswith("curl "):
                            response = f"bash: {command.split()[0]}: command not found\r\n$ "
                        else:
                            response = self.fake_responses["command_not_found"].format(command.split()[0] if command else "")
                        
                        client_socket.send(response.encode('utf-8'))
                
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[ERROR] خطأ في التعامل مع البيانات: {e}")
                    break
        
        except Exception as e:
            print(f"[ERROR] خطأ في التعامل مع العميل: {e}")
        
        finally:
            # تسجيل انتهاء الجلسة
            self.log_interaction(client_ip, client_port, {
                "session_id": session_id,
                "type": "connection_closed",
                "content": "Connection closed"
            })
            
            client_socket.close()
            print(f"[DISCONNECTED] {client_ip}:{client_port}")
    
    def start(self):
        """
        بدء تشغيل مصيدة التسلل
        """
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            self.is_running = True
            print(f"[HONEYPOT STARTED] يستمع على {self.host}:{self.port}")
            print(f"[LOG FILE] السجلات تُحفظ في: {self.log_file}")
            print("[INFO] للإيقاف اضغط Ctrl+C")
            
            while self.is_running:
                try:
                    client_socket, client_address = server_socket.accept()
                    client_socket.settimeout(300)  # 5 دقائق timeout
                    
                    # إنشاء thread منفصل لكل اتصال
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                    self.connection_count += 1
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[ERROR] خطأ في قبول الاتصال: {e}")
        
        except Exception as e:
            print(f"[ERROR] فشل في بدء تشغيل المصيدة: {e}")
        
        finally:
            self.is_running = False
            server_socket.close()
            print("[HONEYPOT STOPPED] تم إيقاف مصيدة التسلل")

def main():
    """
    الدالة الرئيسية لتشغيل مصيدة التسلل
    """
    print("=" * 60)
    print("🍯 مصيدة التسلل التفاعلية - Interactive Honeypot")
    print("=" * 60)
    print()
    
    # إنشاء مصيدة التسلل على المنفذ 2323 (بدلاً من 23 لتجنب الحاجة لصلاحيات root)
    honeypot = TelnetHoneypot(host="0.0.0.0", port=2323)
    
    try:
        honeypot.start()
    except KeyboardInterrupt:
        print("\n[INFO] تم إيقاف المصيدة بواسطة المستخدم")
    except Exception as e:
        print(f"[ERROR] خطأ غير متوقع: {e}")

if __name__ == "__main__":
    main()
