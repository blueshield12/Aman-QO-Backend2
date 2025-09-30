from flask import Flask, request, Response
import requests, time, json, base64

app = Flask(__name__)

API_KEY = "0dabff120b09c5bf795801159af98b0032aa7d44ea04664f1ea311dd64ee08dc"
HEADERS = {"x-apikey": API_KEY}
SCAN_URL = "https://www.virustotal.com/api/v3/urls"
URL_REPORT = "https://www.virustotal.com/api/v3/urls/{}"

def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

def json_response(payload, status=200):
    return add_cors(Response(
        json.dumps(payload, ensure_ascii=False, indent=4),
        content_type="application/json; charset=utf-8"
    )), status

@app.route("/", methods=["GET"])
def scan_url():
    url = request.args.get("url")
    if not url:
        return json_response({"خطأ": "من فضلك أدخل رابط"}, 400)


    try:
        scan_response = requests.post(SCAN_URL, headers=HEADERS, data={"url": url}, timeout=15)
    except requests.RequestException as e:
        return json_response({"خطأ": "فشل في التواصل مع خدمة الفحص", "تفاصيل": str(e)}, 502)

    if scan_response.status_code == 429:
        return json_response({"خطأ": "تم الوصول للحد المسموح من الطلبات (rate limit). حاول بعد شوية."}, 429)
    if scan_response.status_code not in (200, 201):

        return json_response({"خطأ": "فشل إرسال الرابط", "status_code": scan_response.status_code, "body": scan_response.text}, 502)

    try:
        scan_id = scan_response.json().get("data", {}).get("id")
    except Exception:
        return json_response({"خطأ": "استجابة غير متوقعة من خدمة الفحص"}, 502)

    if not scan_id:
        return json_response({"خطأ": "لم نحصل على معرف الفحص (scan_id)."}, 502)

    
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    timeout_seconds = 30
    interval = 2            
    waited = 0
    analysis_data = None

    while waited < timeout_seconds:
        try:
            ar = requests.get(analysis_url, headers=HEADERS, timeout=15)
        except requests.RequestException as e:
            return json_response({"خطأ": "فشل في استعلام نتيجة الفحص", "تفاصيل": str(e)}, 502)

        if ar.status_code == 429:
            return json_response({"خطأ": "تم الوصول للحد المسموح من الطلبات أثناء الانتظار (rate limit)."}, 429)
        if ar.status_code not in (200, 201):
            # لو حصل خطأ، ننتظر ونحاول تاني (أو نكسر لو فشل قاطع)
            time.sleep(interval)
            waited += interval
            continue

        try:
            analysis_data = ar.json()
        except ValueError:
            time.sleep(interval)
            waited += interval
            continue

        status = analysis_data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break

        time.sleep(interval)
        waited += interval

    if not analysis_data or analysis_data.get("data", {}).get("attributes", {}).get("status") != "completed":
        return json_response({
            "message": "التحليل لم يكتمل بعد. يمكنك إعادة المحاولة لاحقًا أو استخدام scan_id للمتابعة.",
            "scan_id": scan_id
        }, 202)

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        report_resp = requests.get(URL_REPORT.format(url_id), headers=HEADERS, timeout=15)
    except requests.RequestException as e:
        return json_response({"خطأ": "فشل في جلب تقرير الرابط النهائي", "تفاصيل": str(e)}, 502)

    if report_resp.status_code == 429:
        return json_response({"خطأ": "تم الوصول للحد المسموح من الطلبات عند جلب التقرير النهائي (rate limit)."}, 429)
    if report_resp.status_code not in (200, 201):
        return json_response({"خطأ": "فشل في جلب تقرير الرابط النهائي", "status_code": report_resp.status_code, "body": report_resp.text}, 502)

    try:
        report = report_resp.json()
    except ValueError:
        return json_response({"خطأ": "استجابة غير صالحة من تقرير الرابط"}, 502)

    last_results = report.get("data", {}).get("attributes", {}).get("last_analysis_results", {}) or {}

    engines = []
    for eng_key, eng_data in last_results.items():
        name = eng_data.get("engine_name") or eng_key
        result = (eng_data.get("result") or "").strip()
        engines.append({"اسم_المحرك": name, "النتيجة": result})

    malicious_engines = [e for e in engines if "malicious" in (e["النتيجة"].lower()) or "trojan" in e["النتيجة"].lower() or "virus" in (e["النتيجة"].lower())]
    phishing_engines = [e for e in engines if "phishing" in (e["النتيجة"].lower()) or "phishing" in (e["النتيجة"].lower())]
    suspicious_engines = [e for e in engines if "suspicious" in (e["النتيجة"].lower()) or "potential" in (e["النتيجة"].lower())]
    clean_engines = [e for e in engines if e not in malicious_engines and e not in phishing_engines and e not in suspicious_engines and e.get("النتيجة")]

    if phishing_engines:
        awareness = "اللينك ده معمول عشان يخدعك ويسرق منك بيانات حساسة زي الباسورد أو أرقام الفيزا. Aman-Qo حماك دلوقتي قبل ما تقع في الفخ."
    elif malicious_engines:
        awareness = " اللينك ده خطير جدًا! مربوط بتنزيل برامج تجسس أو فيروسات ممكن تبوظ موبايلك أو تسرق ملفاتك. ممنوع تفتحه نهائيًا — Aman-Qo بيحمي جهازك."
    elif suspicious_engines:
        awareness = "فيه علامات غريبة في اللينك ده. ممكن يكون جديد لسه محدش جربه، أو ناقصه شهادات أمان. ننصحك تاخد بالك وما تدخلش أي بيانات سرية أو أرقام فيه."
    else:
        awareness = "الينك ده جيد وامن وامن فحص Aman-Qo أكد إن مفيش فيه أي فيروسات أو محاولات نصب. تقدر تكمل وانت مطمّن."
  
    result = {
        "الرابط": url,
        "عدد محركات البحث": len(engines),
        "فحص_امن": clean_engines,
        "فحص_خبيث": malicious_engines,
        "فحص_تصيّد": phishing_engines,
        "فحص_مشبوه": suspicious_engines,
        "توعية": awareness,
    }

    return json_response(result, 200)


if __name__ == "__main__":
    app.run(debug=True)




