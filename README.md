# Hex-NeTMAp







# 🔥 HEX NETMAP PRO v4.0  
### উন্নত নেটওয়ার্ক স্ক্যানার ও ভলনারেবিলিটি অ্যানালাইজার

---

## 🧠 প্রজেক্ট সারাংশ
**HEX NETMAP PRO** হলো একটি উন্নতমানের **LAN Network Mapper** এবং **Vulnerability Assessment Tool**, যা স্থানীয় নেটওয়ার্কের ডিভাইসগুলো সনাক্ত করে, তাদের ওপেন পোর্ট, অপারেটিং সিস্টেম, MAC ঠিকানা, Vendor এবং সম্ভাব্য নিরাপত্তা দুর্বলতা বিশ্লেষণ করে।  
এটি সম্পূর্ণভাবে **Termux ও Python3**-এর উপর ভিত্তি করে তৈরি।

---

## 🎨 প্রধান বৈশিষ্ট্যসমূহ
| বিভাগ | বর্ণনা |
|-------|---------|
| 💠 **Dynamic Banner & Animation** | রঙিন 3D ASCII ব্যানার + রিয়েল-টাইম লোডিং অ্যানিমেশন |
| ⚡ **Smart IP Detection** | Local IP ও নেটওয়ার্ক রেঞ্জ স্বয়ংক্রিয়ভাবে শনাক্ত করে |
| 🔍 **Multithreaded Scan Engine** | সর্বোচ্চ 150 থ্রেডে একসাথে স্ক্যান |
| 🌐 **Advanced Ping Scan** | ICMP, TCP, এবং ARP পিং-এর মাধ্যমে ডিভাইস শনাক্ত করে |
| 🔓 **Port Scanner** | জনপ্রিয় সার্ভিস পোর্ট (21, 22, 23, 80, 443, ইত্যাদি) স্ক্যান করে |
| 🧩 **OS Fingerprinting** | TTL ভিত্তিক OS অনুমান করে (Windows / Linux / Router ইত্যাদি) |
| 🛰️ **MAC Vendor Lookup** | অনলাইন API ব্যবহার করে ডিভাইসের Vendor নাম দেখায় |
| 🧠 **Vulnerability Detection** | সম্ভাব্য সিকিউরিটি রিস্ক (FTP, Telnet, SSH ইত্যাদি) শনাক্ত করে |
| 📊 **Beautiful Result Table** | রঙিন টেবিল আকারে রেজাল্ট দেখায় (`tabulate` মডিউল সহ) |
| 💾 **Report Generator** | রেজাল্ট স্বয়ংক্রিয়ভাবে CSV ও JSON ফাইলে সংরক্ষণ করে |
| 🛡️ **Security & Legal Notice** | ব্যবহারের শেষে সতর্কতা ও আইনগত নির্দেশনা দেখায় |

---

## ⚙️ ইনস্টলেশন নির্দেশনা (Termux)







**চালানোর পর প্রোগ্রাম যা করবে:**
1. ব্যানার ও লোডিং স্ক্রিন দেখাবে (HEX LOGO সহ)
2. Local IP খুঁজে বের করবে  
3. নেটওয়ার্ক রেঞ্জ নির্ধারণ করবে (যেমন `192.168.0.1 - 192.168.0.255`)
4. প্রতিটি IP স্ক্যান করে Alive ডিভাইস খুঁজবে  
5. প্রতিটি ডিভাইসের ওপেন পোর্ট, MAC, OS, Vendor ও Vulnerability দেখাবে  
6. শেষে CSV ও JSON রিপোর্ট তৈরি করবে →  
   `/storage/downloads/hex_netmap_advanced.csv`  
   `/storage/downloads/hex_netmap_advanced.json`

---

## 🧮 আউটপুট উদাহরণ

| IP Address | MAC Address | Hostname | OS | Open Ports | Risk |
|-------------|--------------|-----------|----|-------------|------|
| 192.168.0.2 | 58:CB:52:9A:3F:B1 | android-device | Linux | 22, 80 | 🔴 High |
| 192.168.0.5 | 94:8A:3C:11:4D:7F | DESKTOP-123 | Windows | 445, 3389 | 🟢 Low |

---

## 🧰 সংরক্ষিত ফাইলসমূহ
| ফাইল | অবস্থান | বিবরণ |
|-------|-----------|---------|
| `hex_netmap_pro.py` | মূল টুল কোড | নেটওয়ার্ক স্ক্যান ও বিশ্লেষণ |
| `hex_netmap_advanced.csv` | `/storage/downloads` | টেবিল আকারে রিপোর্ট |
| `hex_netmap_advanced.json` | `/storage/downloads` | JSON ফরম্যাটে বিশদ রিপোর্ট |

---

## ⚠️ নিরাপত্তা ও আইনগত সতর্কতা
> এই টুলটি শুধুমাত্র **শিক্ষা ও অনুমোদিত নেটওয়ার্ক টেস্টিংয়ের জন্য** ব্যবহার করা যাবে।  
> অনুমতি ছাড়া অন্যের নেটওয়ার্ক স্ক্যান করা **অবৈধ** হতে পারে।  
> ব্যবহারের সমস্ত দায়-দায়িত্ব ব্যবহারকারীর নিজের।

---

## 👨‍💻 ডেভেলপার তথ্য
**Tool Name:** HEX NETMAP PRO  
**Version:** 4.0  
**Created By:** Hacker Hex 💻  
**Language:** Python3  
**Tested On:** Termux (Android 12+), Ubuntu, Debian  
**Category:** Ethical Hacking / Network Analysis  

