#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive Honeypot Data Analyzer - Main Launcher
مشروع محلل بيانات مصيدة التسلل التفاعلي - السكريبت الرئيسي

هذا السكريبت يوفر واجهة موحدة لتشغيل جميع أجزاء المشروع
"""

import os
import sys
import subprocess
import time
import threading

def check_requirements():
    """
    فحص المتطلبات المطلوبة
    """
    required_modules = ['pandas', 'matplotlib', 'seaborn', 'requests']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print("⚠️ المكتبات التالية مفقودة:")
        for module in missing_modules:
            print(f"   - {module}")
        print("\nلتثبيت المتطلبات، اكتب:")
        print("pip install -r requirements.txt")
        return False
    
    return True

def run_honeypot():
    """
    تشغيل مصيدة التسلل
    """
    print("🍯 بدء تشغيل مصيدة التسلل...")
    print("="*60)
    
    try:
        # استيراد وتشغيل مصيدة التسلل
        from honeypot_main import main as honeypot_main
        honeypot_main()
    except ImportError:
        print("[ERROR] فشل في استيراد مصيدة التسلل")
        print("تأكد من وجود ملف honeypot_main.py في نفس المجلد")
    except Exception as e:
        print(f"[ERROR] خطأ في تشغيل مصيدة التسلل: {e}")

def run_analyzer():
    """
    تشغيل محلل البيانات
    """
    print("📊 بدء تشغيل محلل البيانات...")
    print("="*60)
    
    try:
        # استيراد وتشغيل محلل البيانات
        from data_analyzer import main as analyzer_main
        analyzer_main()
    except ImportError:
        print("[ERROR] فشل في استيراد محلل البيانات")
        print("تأكد من وجود ملف data_analyzer.py في نفس المجلد")
    except Exception as e:
        print(f"[ERROR] خطأ في تشغيل محلل البيانات: {e}")

def run_demo():
    """
    تشغيل العرض التوضيحي
    """
    print("🎯 بدء العرض التوضيحي...")
    print("="*60)
    print("سيتم إنشاء بيانات تجريبية ثم تحليلها...")
    
    try:
        from data_analyzer import create_sample_data, HoneypotAnalyzer
        
        # إنشاء بيانات تجريبية
        print("\n[1/4] إنشاء بيانات تجريبية...")
        create_sample_data()
        
        # إنشاء محلل
        analyzer = HoneypotAnalyzer()
        
        # تحليل البيانات
        print("\n[2/4] تحليل البيانات...")
        if analyzer.load_data():
            # إنشاء تقرير
            print("\n[3/4] إنشاء التقرير...")
            report = analyzer.generate_report()
            
            # عرض التقرير
            print("\n[4/4] عرض النتائج...")
            print("\n" + "="*80)
            print(report)
            
            # حفظ التقرير
            with open("demo_report.txt", "w", encoding='utf-8') as f:
                f.write(report)
            print(f"\n✅ تم حفظ التقرير في: demo_report.txt")
            
            # إنشاء المخططات البيانية
            try:
                print("\n📈 إنشاء المخططات البيانية...")
                analyzer.create_visualizations()
                print("✅ تم حفظ المخططات في: honeypot_analysis.png")
            except Exception as e:
                print(f"⚠️ تعذر إنشاء المخططات: {e}")
        
        else:
            print("[ERROR] فشل في تحميل البيانات التجريبية")
    
    except Exception as e:
        print(f"[ERROR] خطأ في العرض التوضيحي: {e}")

def simulate_attack():
    """
    محاكاة هجوم على مصيدة التسلل لأغراض الاختبار
    """
    import socket
    import time
    
    def send_attack(host, port, delay=1):
        """إرسال هجوم تجريبي"""
        try:
            # محاولة اتصال
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # استقبال البانر
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"[ATTACK] استقبال: {repr(banner)}")
            
            time.sleep(delay)
            
            # إرسال اسم مستخدم
            sock.send(b"admin\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"[ATTACK] استقبال: {repr(response)}")
            
            time.sleep(delay)
            
            # إرسال كلمة مرور
            sock.send(b"123456\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"[ATTACK] استقبال: {repr(response)}")
            
            time.sleep(delay)
            
            # إرسال بعض الأوامر
            commands = [b"ls\n", b"whoami\n", b"pwd\n", b"exit\n"]
            for cmd in commands:
                sock.send(cmd)
                time.sleep(delay)
                try:
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    print(f"[ATTACK] أمر: {cmd.decode().strip()}, استقبال: {repr(response[:50])}")
                except:
                    break
            
            sock.close()
            print("[ATTACK] انتهى الهجوم التجريبي")
            
        except Exception as e:
            print(f"[ATTACK ERROR] فشل الهجوم التجريبي: {e}")
    
    print("🎯 محاكاة هجوم تجريبي...")
    print("تأكد من تشغيل مصيدة التسلل أولاً على المنفذ 2323")
    input("اضغط Enter للمتابعة...")
    
    # تشغيل عدة هجمات متزامنة
    threads = []
    for i in range(3):
        thread = threading.Thread(target=send_attack, args=("localhost", 2323, 0.5))
        threads.append(thread)
        thread.start()
        time.sleep(1)  # تأخير بين الهجمات
    
    # انتظار انتهاء جميع الهجمات
    for thread in threads:
        thread.join()
    
    print("✅ انتهت محاكاة الهجمات")

def show_project_info():
    """
    عرض معلومات المشروع
    """
    print("="*80)
    print("🍯 مشروع محلل بيانات مصيدة التسلل التفاعلي")
    print("   Interactive Honeypot Data Analyzer")
    print("="*80)
    print()
    print("📋 وصف المشروع:")
    print("   مشروع يجمع بين هندسة الحاسوب والأمن السيبراني")
    print("   يتكون من مصيدة تسلل لاصطياد المهاجمين وأداة تحليل البيانات")
    print()
    print("🔧 المكونات:")
    print("   1. مصيدة التسلل (Honeypot) - محاكاة خدمة Telnet")
    print("   2. محلل البيانات - تحليل وتصور بيانات الهجمات")
    print("   3. واجهة تشغيل موحدة")
    print()
    print("📊 الميزات:")
    print("   • تسجيل محاولات الدخول وكلمات المرور")
    print("   • تحليل الأوامر المُنفذة")
    print("   • إنشاء تقارير تفصيلية")
    print("   • مخططات بيانية تفاعلية")
    print("   • تحليل جغرافي لمصادر الهجمات")
    print()
    print("🛡️ الأهداف الأمنية:")
    print("   • فهم تقنيات المهاجمين")
    print("   • جمع معلومات استخباراتية عن التهديدات")
    print("   • تحسين الدفاعات الأمنية")
    print()
    print("⚠️ تحذير أمني:")
    print("   هذا المشروع للأغراض التعليمية والبحثية فقط")
    print("   كن حذراً عند تعريض أي خدمة للإنترنت")
    print("="*80)

def main():
    """
    الدالة الرئيسية
    """
    # عرض معلومات المشروع
    show_project_info()
    
    # فحص المتطلبات
    if not check_requirements():
        print("\n❌ لا يمكن المتابعة بدون تثبيت المتطلبات")
        return
    
    while True:
        print("\n" + "="*50)
        print("🚀 اختر العملية المطلوبة:")
        print("="*50)
        print("1. 🍯 تشغيل مصيدة التسلل (Honeypot)")
        print("2. 📊 تشغيل محلل البيانات (Data Analyzer)")
        print("3. 🎯 العرض التوضيحي الكامل (Demo)")
        print("4. ⚔️ محاكاة هجوم تجريبي (Simulate Attack)")
        print("5. 📋 عرض معلومات المشروع")
        print("0. 🚪 خروج")
        
        choice = input("\nأدخل اختيارك (0-5): ").strip()
        
        if choice == "1":
            run_honeypot()
        elif choice == "2":
            run_analyzer()
        elif choice == "3":
            run_demo()
        elif choice == "4":
            simulate_attack()
        elif choice == "5":
            show_project_info()
        elif choice == "0":
            print("\n👋 شكراً لاستخدام مشروع محلل بيانات مصيدة التسلل!")
            print("🔒 ابق آمناً في العالم الرقمي!")
            break
        else:
            print("❌ اختيار غير صحيح، حاول مرة أخرى.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ تم إيقاف البرنامج بواسطة المستخدم")
    except Exception as e:
        print(f"\n❌ خطأ غير متوقع: {e}")
