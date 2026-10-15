#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OSINT Graph — Phone + Username + Email. Полные названия операторов."""
import json, re, socket, hashlib, urllib.request, urllib.error, gzip, time, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/122.0 Mobile Safari/537.36"

def http_head(url, timeout=5):
    h = {"User-Agent": UA, "Accept": "text/html,*/*", "Accept-Language": "en-US,en;q=0.9"}
    try:
        req = urllib.request.Request(url, headers=h)
        req.get_method = lambda: "HEAD"
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception: return 0

def http_get(url, timeout=8):
    h = {"User-Agent": UA, "Accept": "text/html,application/json,*/*",
         "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip"}
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            if r.headers.get("Content-Encoding") == "gzip": raw = gzip.decompress(raw)
            return r.status, raw.decode("utf-8", "ignore")
    except urllib.error.HTTPError as e: return e.code, ""
    except Exception: return 0, ""

# ==================== ОПЕРАТОРЫ РФ ====================
RU_OP = {
    "903":"Билайн","905":"Билайн","906":"Билайн","909":"Билайн",
    "960":"Билайн","961":"Билайн","962":"Билайн","963":"Билайн",
    "964":"Билайн","965":"Билайн","966":"Билайн","967":"Билайн",
    "968":"Билайн","969":"Билайн",
    "910":"МТС","911":"МТС","912":"МТС","913":"МТС","914":"МТС",
    "915":"МТС","916":"МТС","917":"МТС","918":"МТС","919":"МТС",
    "980":"МТС","981":"МТС","982":"МТС","983":"МТС","984":"МТС",
    "985":"МТС","987":"МТС","988":"МТС","989":"МТС",
    "920":"МегаФон","921":"МегаФон","922":"МегаФон","923":"МегаФон",
    "924":"МегаФон","925":"МегаФон","926":"МегаФон","927":"МегаФон",
    "928":"МегаФон","929":"МегаФон","930":"МегаФон","931":"МегаФон",
    "932":"МегаФон","933":"МегаФон","934":"МегаФон","936":"МегаФон",
    "937":"МегаФон","938":"МегаФон","939":"МегаФон","999":"МегаФон",
    "900":"Tele2","901":"Tele2","902":"Tele2","904":"Tele2",
    "908":"Tele2","950":"Tele2","951":"Tele2","952":"Tele2",
    "953":"Tele2","958":"Tele2","977":"Tele2","991":"Tele2",
    "992":"Tele2","993":"Tele2","994":"Tele2","995":"Tele2",
    "996":"Tele2","997":"Tele2",
}

RU_OP_FULL = {
    "Билайн": 'ПАО "Вымпел-Коммуникации"',
    "МТС": 'ПАО "МТС"',
    "МегаФон": 'ПАО "МегаФон"',
    "Tele2": 'ООО "Т2 Мобайл"',
    "ВТБ Мобайл": 'ООО "ВТБ Мобайл"',
    "Yota": 'ООО "Скартел"',
    "Ростелеком": 'ПАО "Ростелеком"',
}

# ==================== РЕГИОНЫ РФ (ABC) ====================
RU_ABC = {
    "495":"Москва","499":"Москва","498":"Московская область",
    "812":"Санкт-Петербург","813":"Ленинградская область",
    "383":"Новосибирская область","343":"Свердловская область",
    "843":"Республика Татарстан","861":"Краснодарский край","862":"Краснодарский край",
    "844":"Волгоградская область","473":"Воронежская область",
    "351":"Челябинская область","347":"Республика Башкортостан",
    "846":"Самарская область","845":"Саратовская область",
    "863":"Ростовская область","471":"Курская область","472":"Белгородская область",
    "483":"Брянская область","484":"Калужская область","492":"Владимирская область",
    "493":"Ивановская область","494":"Костромская область","817":"Вологодская область",
    "820":"Вологодская область","821":"Республика Коми","814":"Республика Карелия",
    "818":"Архангельская область","401":"Калининградская область",
    "391":"Красноярский край","395":"Иркутская область","384":"Кемеровская область",
    "385":"Алтайский край","388":"Республика Алтай","301":"Республика Бурятия",
    "302":"Забайкальский край","416":"Амурская область","421":"Хабаровский край",
    "423":"Приморский край","411":"Республика Саха","415":"Камчатский край",
    "413":"Магаданская область","426":"Еврейская АО",
    "487":"Тульская область","491":"Рязанская область","474":"Липецкая область",
    "475":"Тамбовская область","481":"Смоленская область","482":"Тверская область",
    "485":"Ярославская область","486":"Орловская область","815":"Мурманская область",
    "816":"Новгородская область","811":"Псковская область","879":"Ставропольский край",
    "866":"Республика Северная Осетия","867":"Республика Ингушетия",
    "871":"Чеченская Республика","872":"Республика Дагестан",
    "873":"Республика Ингушетия","877":"Республика Адыгея",
    "878":"Карачаево-Черкесия","851":"Астраханская область",
    "353":"Оренбургская область","352":"Курганская область",
    "381":"Омская область","382":"Томская область",
    "390":"Республика Хакасия","394":"Республика Тыва",
    "841":"Пензенская область","842":"Ульяновская область",
    "834":"Республика Мордовия","836":"Республика Марий Эл",
    "835":"Чувашская Республика","855":"Республика Татарстан",
    "341":"Удмуртская Республика","342":"Пермский край",
    "349":"Ямало-Ненецкий АО","346":"Ханты-Мансийский АО",
    "345":"Тюменская область",
}

# ==================== ЧАСОВЫЕ ПОЯСА РФ ====================
RU_TZ = {
    "Калининградская область":"UTC+2 (Калининград)",
    "Москва":"UTC+3 (МСК)","Московская область":"UTC+3 (МСК)",
    "Санкт-Петербург":"UTC+3 (МСК)","Ленинградская область":"UTC+3 (МСК)",
    "Краснодарский край":"UTC+3 (МСК)","Ростовская область":"UTC+3 (МСК)",
    "Воронежская область":"UTC+3 (МСК)","Республика Татарстан":"UTC+3 (МСК)",
    "Республика Башкортостан":"UTC+5 (Екатеринбург)",
    "Самарская область":"UTC+4 (Самара)","Саратовская область":"UTC+4 (Самара)",
    "Ульяновская область":"UTC+4 (Ульяновск)","Астраханская область":"UTC+4 (Астрахань)",
    "Волгоградская область":"UTC+4 (Волгоград)",
    "Свердловская область":"UTC+5 (Екатеринбург)","Челябинская область":"UTC+5 (Екатеринбург)",
    "Пермский край":"UTC+5 (Пермь)","Оренбургская область":"UTC+5 (Оренбург)",
    "Курганская область":"UTC+5 (Курган)","Тюменская область":"UTC+5 (Тюмень)",
    "Ханты-Мансийский АО":"UTC+5 (Ханты-Мансийск)","Ямало-Ненецкий АО":"UTC+5 (Салехард)",
    "Омская область":"UTC+6 (Омск)","Новосибирская область":"UTC+7 (Новосибирск)",
    "Томская область":"UTC+7 (Томск)","Кемеровская область":"UTC+7 (Кемерово)",
    "Красноярский край":"UTC+7 (Красноярск)","Республика Хакасия":"UTC+7 (Абакан)",
    "Республика Тыва":"UTC+7 (Кызыл)",
    "Иркутская область":"UTC+8 (Иркутск)","Республика Бурятия":"UTC+8 (Улан-Удэ)",
    "Забайкальский край":"UTC+9 (Чита)","Республика Саха":"UTC+9 (Якутск)",
    "Амурская область":"UTC+9 (Благовещенск)",
    "Хабаровский край":"UTC+10 (Хабаровск)","Приморский край":"UTC+10 (Владивосток)",
    "Еврейская АО":"UTC+10 (Биробиджан)",
    "Магаданская область":"UTC+11 (Магадан)",
    "Камчатский край":"UTC+12 (Петропавловск-Камчатский)",
}

# ==================== ОПЕРАТОРЫ КАЗАХСТАНА ====================
KZ_OP = {
    "700":"Altel","701":"Beeline KZ","702":"Beeline KZ","705":"Beeline KZ",
    "706":"Beeline KZ","707":"Tele2 KZ","708":"Tele2 KZ","747":"Tele2 KZ",
    "771":"Beeline KZ","775":"Beeline KZ","776":"Beeline KZ",
    "777":"Beeline KZ","778":"Beeline KZ",
}

KZ_OP_FULL = {
    "Altel": 'АО "Altel"',
    "Beeline KZ": 'ТОО "Кар-Тел" (Beeline)',
    "Tele2 KZ": 'ТОО "Мобайл Телеком-Сервис" (Tele2)',
    "Kcell": 'АО "Кселл" (Kcell)',
    "Activ": 'АО "Кселл" (Activ)',
}

KZ_CITY = {
    "717":"Астана","7172":"Астана",
    "727":"Алматы","7272":"Алматы",
    "712":"Атырау","7122":"Атырау",
    "713":"Актобе","7132":"Актобе",
    "714":"Костанай","7142":"Костанай",
    "715":"Кокшетау","7152":"Кокшетау",
    "716":"Караганда","7162":"Караганда",
    "718":"Павлодар","7182":"Павлодар",
    "721":"Шымкент","7212":"Шымкент",
    "722":"Семей","7222":"Семей",
    "723":"Усть-Каменогорск","7232":"Усть-Каменогорск",
    "724":"Кызылорда","7242":"Кызылорда",
    "725":"Тараз","7252":"Тараз",
    "726":"Талдыкорган","7262":"Талдыкорган",
    "728":"Актау","7282":"Актау",
}

KZ_TZ = {
    "Астана":"UTC+5","Алматы":"UTC+5","Атырау":"UTC+5","Актобе":"UTC+5",
    "Костанай":"UTC+5","Кокшетау":"UTC+5","Караганда":"UTC+5","Павлодар":"UTC+5",
    "Шымкент":"UTC+5","Семей":"UTC+5","Усть-Каменогорск":"UTC+5",
    "Кызылорда":"UTC+5","Тараз":"UTC+5","Талдыкорган":"UTC+5","Актау":"UTC+5",
}

# ==================== ОПЕРАТОРЫ БЕЛАРУСИ ====================
BY_OP = {
    "291":"A1","292":"A1","293":"A1","294":"A1","295":"A1",
    "296":"A1","297":"A1","298":"A1","299":"A1",
    "331":"МТС","332":"МТС","333":"МТС","334":"МТС",
    "335":"МТС","336":"МТС","337":"МТС","338":"МТС","339":"МТС",
    "441":"life:)","442":"life:)","443":"life:)","444":"life:)",
    "445":"life:)","446":"life:)","447":"life:)","448":"life:)","449":"life:)",
}

BY_OP_FULL = {
    "A1": 'УП "А1" (Velcom)',
    "МТС": 'СООО "МТС"',
    "life:)": 'ООО "Белорусские облачные технологии" (life:)',
}

BY_CITY = {
    "17":"Минск","173":"Минская область",
    "162":"Брест","163":"Брестская область",
    "212":"Витебск","213":"Витебская область",
    "232":"Гомель","233":"Гомельская область",
    "152":"Гродно","153":"Гродненская область",
    "222":"Могилёв","223":"Могилёвская область",
}

BY_TZ = {
    "Минск":"UTC+3","Минская область":"UTC+3",
    "Брест":"UTC+3","Брестская область":"UTC+3",
    "Витебск":"UTC+3","Витебская область":"UTC+3",
    "Гомель":"UTC+3","Гомельская область":"UTC+3",
    "Гродно":"UTC+3","Гродненская область":"UTC+3",
    "Могилёв":"UTC+3","Могилёвская область":"UTC+3",
}

# ==================== ОПЕРАТОРЫ УКРАИНЫ ====================
UA_OP = {
    "50":"Vodafone","63":"lifecell","66":"Vodafone","67":"Kyivstar",
    "68":"Kyivstar","73":"lifecell","91":"3Mob","92":"PEOPLEnet",
    "93":"lifecell","94":"Intertelecom","95":"Vodafone","96":"Kyivstar",
    "97":"Kyivstar","98":"Kyivstar","99":"Vodafone",
}

UA_OP_FULL = {
    "Kyivstar": 'ПрАО "Киевстар"',
    "Vodafone": 'ПрАО "ВФ Украина"',
    "lifecell": 'ООО "лайфселл"',
    "3Mob": 'ООО "ТриМоб"',
    "Intertelecom": 'ООО "Интертелеком"',
}

# ==================== СЕРВИСЫ ПО НОМЕРУ ====================
PHONE_SERVICES = [
    ("telegram","Telegram","https://t.me/+{u}","#2AABEE","send",True,"head"),
    ("whatsapp","WhatsApp","https://wa.me/{u}","#25D366","chat",False,"head"),
    ("viber","Viber","https://invite.viber.com/?number=%2B{u}","#7360F2","call",False,"head"),
    ("signal","Signal","https://signal.me/#p/+{u}","#3A76F0","lock",False,"head"),
    ("spamcalls","SpamCalls","https://spamcalls.net/en/number/{u}","#FF5722","shield",True,"parse_reports"),
    ("shouldianswer","Should I Answer","https://www.shouldianswer.net/phones/{u}","#EF4444","help",True,"parse_rating"),
    ("tellows","Tellows","https://www.tellows.ru/num/{u}","#E91E63","warn",False,"parse_generic"),
    ("whocallsme","WhoCallsMe","https://whocallsme.com/Phone-Number.aspx/{u}","#9C27B0","help",False,"parse_generic"),
    ("800notes","800notes","https://800notes.com/Phone.aspx/{u}","#00BCD4","hash",False,"parse_generic"),
    ("hibp","HIBP","https://haveibeenpwned.com/unifiedsearch/{u}","#D32F2F","unlock",False,"parse_breach"),
    ("leakcheck","LeakCheck","https://leakcheck.io/?query={u}","#9C27B0","drop",False,"parse_breach"),
    ("numlookup","NumLookup","https://www.numlookup.com/phone/{u}","#4CAF50","hash",False,"parse_carrier"),
    ("freelookup","Free-Lookup","https://free-lookup.net/{u}","#00ACC1","globe",False,"parse_generic"),
]

def parse_reports(html):
    if not html: return 0
    if not re.search(r'report', html, re.I): return 0
    for pat in [r'"ratingCount"\s*:\s*(\d+)', r'(\d{1,4})\s+reports?\b',
                r'reports?\s*[:>\-]\s*(\d{1,4})\b', r'class="[^"]*report[^"]*"[^>]*>\s*(\d{1,4})']:
        m = re.search(pat, html, re.I)
        if m:
            try: return int(m.group(1))
            except: pass
    return 0

def parse_rating(html):
    if not html: return None
    m = re.search(r'(\d\.\d)\s*/\s*5', html, re.I)
    if m: return m.group(1)
    m = re.search(r'rating[^0-9]{0,20}(\d+(?:\.\d+)?)\s*(?:/\s*5|%)', html, re.I)
    if m: return m.group(1)
    return None

def parse_carrier(html):
    if not html: return None
    m = re.search(r'(?:carrier|operator)[^>]{0,50}>([^<]+)<', html, re.I)
    if m:
        v = m.group(1).strip()
        if 2 < len(v) < 40: return v
    return None

def parse_breach(html):
    if not html: return None
    if re.search(r'good news|no pwnage|not been pwned|no breach', html, re.I): return "нет утечек"
    if re.search(r'pwned|breach', html, re.I): return "есть утечки"
    return None

def parse_generic(html):
    if not html: return None
    if not re.search(r'\d{7,}', html): return None
    if re.search(r'not found|no data|никогда не было|не найдено', html, re.I): return None
    m = re.search(r'(\d+)\s+(?:комментар|comment|report|жалоб|rating)', html, re.I)
    if m:
        try: return f"{m.group(1)} отзывов"
        except: pass
    return "есть данные"

def check_phone_services(phone_digits, deadline=25):
    start = time.time()
    def one(p):
        if time.time() - start > deadline: return None
        pid, name, tpl, color, icon, reliable, parser = p
        url = tpl.format(u=phone_digits)
        if parser == "head":
            c = http_head(url, timeout=5)
            if c == 200:
                return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                        "status":"found","code":c,"reliable":reliable,
                        "username":phone_digits,"sub":"найден"}
            return None
        c, html = http_get(url, timeout=6)
        if parser == "parse_reports":
            if c != 200: return None
            reports = parse_reports(html)
            has_entry = re.search(rf'{phone_digits}|No reports|no reports yet', html, re.I)
            if not has_entry: return None
            return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                    "status":"found","code":c,"reliable":reliable,
                    "username":phone_digits,"sub":f"{reports} репортов"}
        if parser == "parse_rating":
            if c != 200: return None
            rating = parse_rating(html)
            if not rating: return None
            return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                    "status":"found","code":c,"reliable":reliable,
                    "username":phone_digits,"sub":f"рейтинг: {rating}"}
        if parser == "parse_carrier":
            if c != 200: return None
            carrier = parse_carrier(html)
            if not carrier: return None
            return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                    "status":"found","code":c,"reliable":reliable,
                    "username":phone_digits,"sub":f"оператор: {carrier}"}
        if parser == "parse_breach":
            if c != 200: return None
            breach = parse_breach(html)
            if breach != "есть утечки": return None
            return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                    "status":"found","code":c,"reliable":reliable,
                    "username":phone_digits,"sub":breach}
        if parser == "parse_generic":
            if c != 200: return None
            info = parse_generic(html)
            if not info: return None
            return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                    "status":"found","code":c,"reliable":reliable,
                    "username":phone_digits,"sub":info}
        return None
    out = []
    with ThreadPoolExecutor(max_workers=13) as ex:
        for r in ex.map(one, PHONE_SERVICES):
            if r: out.append(r)
    if not any(r["id"] == "telegram" for r in out):
        out.append({"id":"telegram","name":"Telegram",
                    "url":f"https://t.me/+{phone_digits}",
                    "color":"#2AABEE","icon":"send","status":"unknown",
                    "code":0,"reliable":True,"username":phone_digits,"sub":"не найден"})
    dorks = [
        ("Google",f'https://www.google.com/search?q="%2B{phone_digits}"',"google"),
        ("Bing",f'https://www.bing.com/search?q="%2B{phone_digits}"',"bing"),
        ("Yandex",f'https://yandex.ru/search/?text="%2B{phone_digits}"',"yandex"),
        ("DDG",f'https://duckduckgo.com/?q="%2B{phone_digits}"',"ddg"),
    ]
    for nm,url,icon in dorks:
        out.append({"id":f"dork_{icon}","name":nm,"url":url,"color":"#6366f1",
                    "icon":icon,"status":"unknown","code":0,"reliable":True,
                    "username":phone_digits,"sub":"поиск"})
    out.sort(key=lambda r: (0 if r["id"]=="telegram" else 1, 0 if r["status"]=="found" else 1))
    return out

# ==================== 100 ПЛАТФОРМ ДЛЯ НИКА ====================
PLATFORMS = [
    ("github","GitHub","https://github.com/{u}","#8b949e","github",True),
    ("gitlab","GitLab","https://gitlab.com/{u}","#FC6D26","work",True),
    ("bitbucket","Bitbucket","https://bitbucket.org/{u}/","#0052CC","work",True),
    ("codeberg","Codeberg","https://codeberg.org/{u}","#2185D0","work",True),
    ("sourceforge","SourceForge","https://sourceforge.net/u/{u}/profile","#FF6600","work",True),
    ("replit","Replit","https://replit.com/@{u}","#F26207","work",True),
    ("codepen","CodePen","https://codepen.io/{u}","#000000","work",True),
    ("jsfiddle","JSFiddle","https://jsfiddle.net/user/{u}/","#0084FF","work",True),
    ("kaggle","Kaggle","https://www.kaggle.com/{u}","#20BEFF","work",True),
    ("codeforces","Codeforces","https://codeforces.com/profile/{u}","#1F8ACB","work",True),
    ("codewars","Codewars","https://www.codewars.com/users/{u}","#B1361E","work",True),
    ("tryhackme","TryHackMe","https://tryhackme.com/p/{u}","#C11111","shield",True),
    ("hackerone","HackerOne","https://hackerone.com/{u}","#FF3A30","shield",True),
    ("bugcrowd","Bugcrowd","https://bugcrowd.com/{u}","#F26722","shield",True),
    ("hn","Hacker News","https://news.ycombinator.com/user?id={u}","#FF6600","work",True),
    ("lobsters","Lobsters","https://lobste.rs/~{u}","#AC130D","work",True),
    ("devto","DEV.to","https://dev.to/{u}","#0A0A0A","work",True),
    ("hashnode","Hashnode","https://hashnode.com/@{u}","#2962FF","work",True),
    ("reddit","Reddit","https://www.reddit.com/user/{u}","#FF4500","chat",True),
    ("vk","VK","https://vk.com/{u}","#0077FF","globe",True),
    ("ok","OK","https://ok.ru/{u}","#EE8208","globe",True),
    ("tumblr","Tumblr","https://{u}.tumblr.com","#36465D","globe",True),
    ("flickr","Flickr","https://www.flickr.com/people/{u}","#FF0084","cam",True),
    ("deviantart","DeviantArt","https://www.deviantart.com/{u}","#05CC47","cam",True),
    ("behance","Behance","https://www.behance.net/{u}","#1769FF","cam",True),
    ("dribbble","Dribbble","https://dribbble.com/{u}","#EA4C89","cam",True),
    ("vimeo","Vimeo","https://vimeo.com/{u}","#1AB7EA","play",True),
    ("youtube","YouTube","https://www.youtube.com/@{u}","#FF0000","play",True),
    ("twitch","Twitch","https://www.twitch.tv/{u}","#9146FF","play",True),
    ("patreon","Patreon","https://www.patreon.com/{u}","#F96854","globe",True),
    ("mastodon","Mastodon","https://mastodon.social/@{u}","#6364FF","globe",True),
    ("soundcloud","SoundCloud","https://soundcloud.com/{u}","#FF5500","music",True),
    ("bandcamp","Bandcamp","https://{u}.bandcamp.com","#629AA9","music",True),
    ("mixcloud","Mixcloud","https://www.mixcloud.com/{u}/","#5000FF","music",True),
    ("lastfm","Last.fm","https://www.last.fm/user/{u}","#D51007","music",True),
    ("discogs","Discogs","https://www.discogs.com/user/{u}","#333333","music",True),
    ("reverbnation","ReverbNation","https://www.reverbnation.com/{u}","#E43525","music",True),
    ("audiomack","Audiomack","https://audiomack.com/{u}","#FFA200","music",True),
    ("medium","Medium","https://medium.com/@{u}","#ffffff","work",True),
    ("substack","Substack","https://{u}.substack.com","#FF6719","work",True),
    ("wordpress","WordPress","https://{u}.wordpress.com","#21759B","work",True),
    ("blogger","Blogger","https://{u}.blogspot.com","#FF5722","work",True),
    ("wattpad","Wattpad","https://www.wattpad.com/user/{u}","#FF6122","work",True),
    ("archiveofourown","AO3","https://archiveofourown.org/users/{u}","#900000","work",True),
    ("fanfiction","FanFiction","https://www.fanfiction.net/u/{u}","#1E4B7B","work",True),
    ("quotev","Quotev","https://www.quotev.com/{u}","#00B4D8","work",True),
    ("goodreads","Goodreads","https://www.goodreads.com/{u}","#372213","work",True),
    ("letterboxd","Letterboxd","https://letterboxd.com/{u}/","#00E054","play",True),
    ("myanimelist","MyAnimeList","https://myanimelist.net/profile/{u}","#2E51A2","play",True),
    ("anilist","AniList","https://anilist.co/user/{u}","#02A9FF","play",True),
    ("trakt","Trakt","https://trakt.tv/users/{u}","#ED1C24","play",True),
    ("steam","Steam","https://steamcommunity.com/id/{u}","#171a21","game",True),
    ("xbox","Xbox","https://xboxgamertag.com/search/{u}","#107C10","game",True),
    ("chess","Chess.com","https://www.chess.com/member/{u}","#7FA650","game",True),
    ("lichess","Lichess","https://lichess.org/@/{u}","#BF811D","game",True),
    ("aboutme","About.me","https://about.me/{u}","#00A8FF","user",True),
    ("keybase","Keybase","https://keybase.io/{u}","#FF6F21","lock",True),
    ("disqus","Disqus","https://disqus.com/by/{u}/","#2E9FFF","chat",True),
    ("trello","Trello","https://trello.com/{u}","#0079BF","work",True),
    ("ebay","eBay","https://www.ebay.com/usr/{u}","#E53238","work",True),
    ("ko-fi","Ko-fi","https://ko-fi.com/{u}","#29ABE0","work",True),
    ("buymeacoffee","Buy Me a Coffee","https://www.buymeacoffee.com/{u}","#FFDD00","work",True),
    ("gumroad","Gumroad","https://{u}.gumroad.com","#FF90E8","work",True),
    ("telegram","Telegram","https://t.me/{u}","#2AABEE","send",True),
    ("linktr","Linktree","https://linktr.ee/{u}","#39E09B","globe",True),
    ("carrd","Carrd","https://{u}.carrd.co","#00B2FF","globe",True),
    ("beacons","Beacons","https://beacons.ai/{u}","#4169E1","globe",True),
    ("instagram","Instagram","https://www.instagram.com/{u}/","#E4405F","cam",False),
    ("twitter","Twitter/X","https://x.com/{u}","#1DA1F2","chat",False),
    ("tiktok","TikTok","https://www.tiktok.com/@{u}","#ffffff","play",False),
    ("linkedin","LinkedIn","https://www.linkedin.com/in/{u}","#0A66C2","work",False),
    ("facebook","Facebook","https://www.facebook.com/{u}","#1877F2","globe",False),
]

def check_platforms(username, deadline=25, limit=10):
    start = time.time()
    def one(p):
        if time.time() - start > deadline: return None
        pid, name, tpl, color, icon, reliable = p
        url = tpl.format(u=username)
        c = http_head(url, timeout=4)
        if c == 200:
            return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                    "status":"found","code":c,"reliable":reliable,"username":username,
                    "sub":"найден"}
        return None
    all_results = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        for r in ex.map(one, PLATFORMS):
            if r: all_results.append(r)
    all_results.sort(key=lambda r: 0 if r["reliable"] else 1)
    tg = next((r for r in all_results if r["id"] == "telegram"), None)
    if tg is None:
        tg = {"id":"telegram","name":"Telegram","url":f"https://t.me/{username}",
              "color":"#2AABEE","icon":"send","status":"unknown","code":0,
              "reliable":True,"username":username,"sub":"не найден"}
    top = [r for r in all_results[:limit] if r["id"] != "telegram"]
    top = top[:limit-1]; top.append(tg)
    return top

# ==================== EMAIL ====================
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

EMAIL_PLATFORMS = [
    ("github","GitHub","https://github.com/{l}","#8b949e","github",True),
    ("reddit","Reddit","https://www.reddit.com/user/{l}","#FF4500","chat",True),
    ("telegram","Telegram","https://t.me/{l}","#2AABEE","send",True),
    ("vk","VK","https://vk.com/{l}","#0077FF","globe",True),
    ("youtube","YouTube","https://www.youtube.com/@{l}","#FF0000","play",True),
    ("twitch","Twitch","https://www.twitch.tv/{l}","#9146FF","play",True),
    ("steam","Steam","https://steamcommunity.com/id/{l}","#171a21","game",True),
    ("soundcloud","SoundCloud","https://soundcloud.com/{l}","#FF5500","music",True),
    ("mastodon","Mastodon","https://mastodon.social/@{l}","#6364FF","globe",True),
    ("keybase","Keybase","https://keybase.io/{l}","#FF6F21","lock",True),
    ("devto","DEV.to","https://dev.to/{l}","#0A0A0A","work",True),
    ("hn","Hacker News","https://news.ycombinator.com/user?id={l}","#FF6600","work",True),
    ("medium","Medium","https://medium.com/@{l}","#ffffff","work",True),
    ("aboutme","About.me","https://about.me/{l}","#00A8FF","user",True),
    ("linktr","Linktree","https://linktr.ee/{l}","#39E09B","globe",True),
    ("behance","Behance","https://www.behance.net/{l}","#1769FF","cam",True),
    ("dribbble","Dribbble","https://dribbble.com/{l}","#EA4C89","cam",True),
    ("flickr","Flickr","https://www.flickr.com/people/{l}","#FF0084","cam",True),
]

def check_email_services(email, deadline=25):
    login, domain = email.split("@",1)
    md5 = hashlib.md5(email.lower().encode()).hexdigest()
    start = time.time()

    def one(p):
        if time.time() - start > deadline: return None
        pid, name, tpl, color, icon, reliable = p
        url = tpl.format(l=login)
        c = http_head(url, timeout=4)
        if c == 200:
            return {"id":pid,"name":name,"url":url,"color":color,"icon":icon,
                    "status":"found","code":c,"reliable":reliable,
                    "username":login,"sub":f"@{login}"}
        return None

    out = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(one, EMAIL_PLATFORMS):
            if r: out.append(r)

    gc = http_head(f"https://www.gravatar.com/avatar/{md5}?d=404", timeout=6)
    if gc == 200:
        out.append({"id":"gravatar","name":"Gravatar","url":f"https://gravatar.com/{md5}",
                    "color":"#1E8CBE","icon":"cam","status":"found","code":gc,
                    "reliable":True,"username":login,"sub":"есть аватар"})
        jc, jbody = http_get(f"https://gravatar.com/{md5}.json", timeout=8)
        if jc == 200 and jbody:
            try:
                profile = json.loads(jbody)
                entry = profile.get("entry") or {}
                if isinstance(entry, list): entry = entry[0] if entry else {}
                name = entry.get("displayName")
                if not name and isinstance(entry.get("name"), dict):
                    name = entry["name"].get("formatted")
                if name:
                    out.append({"id":"gv_name","name":"Имя","url":f"https://gravatar.com/{md5}",
                                "color":"#8b5cf6","icon":"user","status":"found","code":200,
                                "reliable":True,"username":login,"sub":str(name)[:60]})
                loc = entry.get("currentLocation") or entry.get("location")
                if loc:
                    out.append({"id":"gv_loc","name":"Локация","url":f"https://gravatar.com/{md5}",
                                "color":"#f59e0b","icon":"globe","status":"found","code":200,
                                "reliable":True,"username":login,"sub":str(loc)[:60]})
                about = entry.get("aboutMe") or entry.get("description")
                if about:
                    out.append({"id":"gv_bio","name":"Bio","url":f"https://gravatar.com/{md5}",
                                "color":"#10b981","icon":"chat","status":"found","code":200,
                                "reliable":True,"username":login,"sub":str(about)[:60]})
                for i, acc in enumerate((entry.get("accounts") or [])[:5]):
                    shortname = (acc.get("shortname") or "").strip()
                    uname = (acc.get("username") or "").strip()
                    url = (acc.get("url") or "").strip()
                    if shortname and uname:
                        out.append({"id":f"gv_acc_{shortname}_{i}","name":shortname.capitalize(),
                                    "url":url or f"https://gravatar.com/{md5}",
                                    "color":"#3b82f6","icon":"globe","status":"found","code":200,
                                    "reliable":True,"username":login,"sub":f"@{uname}"})
                for i, acc in enumerate((entry.get("verified_accounts") or [])[:5]):
                    service = (acc.get("service_type") or "").strip()
                    uname = (acc.get("username") or "").strip()
                    url = (acc.get("url") or "").strip()
                    if service and uname:
                        out.append({"id":f"gv_v_{service}_{i}","name":f"✓ {service.capitalize()}",
                                    "url":url or f"https://gravatar.com/{md5}",
                                    "color":"#22c55e","icon":"shield","status":"found","code":200,
                                    "reliable":True,"username":login,"sub":f"@{uname}"})
            except Exception: pass

    for rtype,label in [("MX","MX"),("TXT","SPF/DMARC"),("A","A-запись")]:
        c, body = http_get(f"https://dns.google/resolve?name={domain}&type={rtype}", timeout=6)
        if c == 200:
            try:
                d = json.loads(body)
                for a in d.get("Answer",[]):
                    data = a.get("data","")[:60]
                    nid = f"dns_{rtype}_{data[:15]}"
                    out.append({"id":nid,"name":label,"url":f"https://dns.google/query?name={domain}&type={rtype}",
                                "color":"#3B82F6","icon":"globe","status":"found",
                                "code":200,"reliable":True,"username":login,"sub":data})
            except: pass

    dorks = [
        ("Google",f'https://www.google.com/search?q="%22{email}%22"',"google"),
        ("Bing",f'https://www.bing.com/search?q="%22{email}%22"',"bing"),
        ("Yandex",f'https://yandex.ru/search/?text="%22{email}%22"',"yandex"),
        ("DDG",f'https://duckduckgo.com/?q="%22{email}%22"',"ddg"),
        ("LeakCheck",f'https://leakcheck.io/?query={email}',"ddg"),
        ("Dehashed",f'https://dehashed.com/search?query={email}',"lock"),
    ]
    for nm,url,icon in dorks:
        out.append({"id":f"edork_{nm}","name":nm,"url":url,"color":"#6366f1",
                    "icon":icon,"status":"unknown","code":0,"reliable":True,
                    "username":login,"sub":"поиск"})

    out.sort(key=lambda r: (0 if r["status"]=="found" else 1, 0 if r["reliable"] else 1))
    return out

# ==================== ТЕЛЕФОН ====================
CC = {
    "1":("US","США/Канада"),"7":("RU","Россия/Казахстан"),"20":("EG","Египет"),
    "27":("ZA","ЮАР"),"30":("GR","Греция"),"31":("NL","Нидерланды"),
    "32":("BE","Бельгия"),"33":("FR","Франция"),"34":("ES","Испания"),
    "36":("HU","Венгрия"),"39":("IT","Италия"),"40":("RO","Румыния"),
    "41":("CH","Швейцария"),"43":("AT","Австрия"),"44":("GB","Великобритания"),
    "45":("DK","Дания"),"46":("SE","Швеция"),"47":("NO","Норвегия"),
    "48":("PL","Польша"),"49":("DE","Германия"),"51":("PE","Перу"),
    "52":("MX","Мексика"),"54":("AR","Аргентина"),"55":("BR","Бразилия"),
    "56":("CL","Чили"),"57":("CO","Колумбия"),"60":("MY","Малайзия"),
    "61":("AU","Австралия"),"62":("ID","Индонезия"),"63":("PH","Филиппины"),
    "64":("NZ","Новая Зеландия"),"65":("SG","Сингапур"),"66":("TH","Таиланд"),
    "81":("JP","Япония"),"82":("KR","Корея"),"84":("VN","Вьетнам"),
    "86":("CN","Китай"),"90":("TR","Турция"),"91":("IN","Индия"),
    "92":("PK","Пакистан"),"93":("AF","Афганистан"),"94":("LK","Шри-Ланка"),
    "95":("MM","Мьянма"),"98":("IR","Иран"),"212":("MA","Марокко"),
    "213":("DZ","Алжир"),"216":("TN","Тунис"),"218":("LY","Ливия"),
    "220":("GM","Гамбия"),"221":("SN","Сенегал"),"234":("NG","Нигерия"),
    "254":("KE","Кения"),"255":("TZ","Танзания"),"256":("UG","Уганда"),
    "260":("ZM","Замбия"),"263":("ZW","Зимбабве"),"351":("PT","Португалия"),
    "352":("LU","Люксембург"),"353":("IE","Ирландия"),"354":("IS","Исландия"),
    "355":("AL","Албания"),"356":("MT","Мальта"),"357":("CY","Кипр"),
    "358":("FI","Финляндия"),"359":("BG","Болгария"),"370":("LT","Литва"),
    "371":("LV","Латвия"),"372":("EE","Эстония"),"373":("MD","Молдова"),
    "374":("AM","Армения"),"375":("BY","Беларусь"),"376":("AD","Андорра"),
    "377":("MC","Монако"),"380":("UA","Украина"),"381":("RS","Сербия"),
    "382":("ME","Черногория"),"383":("XK","Косово"),"385":("HR","Хорватия"),
    "386":("SI","Словения"),"387":("BA","Босния"),"389":("MK","Македония"),
    "420":("CZ","Чехия"),"421":("SK","Словакия"),"423":("LI","Лихтенштейн"),
    "501":("BZ","Белиз"),"502":("GT","Гватемала"),"503":("SV","Сальвадор"),
    "504":("HN","Гондурас"),"505":("NI","Никарагуа"),"506":("CR","Коста-Рика"),
    "507":("PA","Панама"),"591":("BO","Боливия"),"592":("GY","Гайана"),
    "593":("EC","Эквадор"),"595":("PY","Парагвай"),"598":("UY","Уругвай"),
    "673":("BN","Бруней"),"850":("KP","КНДР"),"852":("HK","Гонконг"),
    "853":("MO","Макао"),"855":("KH","Камбоджа"),"856":("LA","Лаос"),
    "880":("BD","Бангладеш"),"886":("TW","Тайвань"),"960":("MV","Мальдивы"),
    "961":("LB","Ливан"),"962":("JO","Иордания"),"963":("SY","Сирия"),
    "964":("IQ","Ирак"),"965":("KW","Кувейт"),"966":("SA","Саудия"),
    "967":("YE","Йемен"),"968":("OM","Оман"),"971":("AE","ОАЭ"),
    "972":("IL","Израиль"),"973":("BH","Бахрейн"),"974":("QA","Катар"),
    "975":("BT","Бутан"),"976":("MN","Монголия"),"977":("NP","Непал"),
    "992":("TJ","Таджикистан"),"993":("TM","Туркмения"),"994":("AZ","Азербайджан"),
    "995":("GE","Грузия"),"996":("KG","Киргизия"),"998":("UZ","Узбекистан"),
}

def detect_cc(digits):
    for n in (3,2,1):
        if len(digits) >= n and digits[:n] in CC:
            return digits[:n], CC[digits[:n]]
    return None,(None,None)

def parse_phone(raw):
    d = re.sub(r"\D","",raw)
    if not d: return None
    if d.startswith("8") and len(d)==11: d = "7"+d[1:]
    if d.startswith("00"): d = d[2:]
    code,(iso,country) = detect_cc(d)
    if not code: return None
    nat = d[len(code):]
    op = None
    region = None
    tz = None

    if code == "7":
        # +7 — Россия или Казахстан. Различаем по префиксу.
        pref = nat[:3]
        if pref in KZ_OP:
            iso, country = "KZ", "Казахстан"
            op = KZ_OP.get(pref)
            op_full = KZ_OP_FULL.get(op, op) if op else None
            op = op_full or op
        elif pref in RU_OP:
            iso, country = "RU", "Россия"
            op_short = RU_OP.get(pref)
            op = RU_OP_FULL.get(op_short, op_short) if op_short else None
        elif pref in RU_ABC:
            iso, country = "RU", "Россия"
            region = RU_ABC.get(pref)
            tz = RU_TZ.get(region) if region else None
        elif pref in KZ_CITY:
            iso, country = "KZ", "Казахстан"
            region = KZ_CITY.get(pref)
            tz = KZ_TZ.get(region) if region else None
        elif pref in BY_OP:
            iso, country = "BY", "Беларусь"
            op_short = BY_OP.get(pref)
            op = BY_OP_FULL.get(op_short, op_short) if op_short else None
        else:
            iso, country = "RU", "Россия"
    elif iso == "BY":
        pref = nat[:3]
        op_short = BY_OP.get(pref)
        op = BY_OP_FULL.get(op_short, op_short) if op_short else None
        pref2 = nat[:2]
        if not op and pref2 in BY_CITY:
            region = BY_CITY.get(pref2)
            tz = BY_TZ.get(region) if region else None
    elif iso == "UA":
        pref = nat[:2]
        op_short = UA_OP.get(pref)
        op = UA_OP_FULL.get(op_short, op_short) if op_short else None

    ptype = "мобильный" if nat and nat[0] in "679" else ("стационарный" if nat and nat[0] in "12345" else "неизвестно")
    return {"digits":d,"e164":"+"+d,"country":country,"iso":iso,
            "national":nat,"operator":op or "неизвестен",
            "region":region or "","tz":tz or "","type":ptype}

# ==================== ГРАФЫ ====================
def build_graph(phone_raw):
    p = parse_phone(phone_raw)
    if not p: return {"error":"невалидный номер"}
    nodes = []; edges = []
    root_id = "phone"
    nodes.append({"id":root_id,"label":p["e164"],"type":"phone","icon":"phone","color":"#8b5cf6"})
    nodes.append({"id":"operator","label":p["operator"],"type":"operator",
                  "icon":"tower","color":"#3B82F6","sub":f'{p["country"]} • {p["type"]}'})
    edges.append({"source":root_id,"target":"operator","label":"оператор"})
    nodes.append({"id":"country","label":p["country"],"type":"country",
                  "icon":"globe","color":"#10B981","sub":p["iso"]})
    edges.append({"source":root_id,"target":"country","label":"страна"})
    if p.get("region"):
        nodes.append({"id":"region","label":p["region"],"type":"region",
                      "icon":"globe","color":"#F59E0B","sub":"регион выдачи"})
        edges.append({"source":root_id,"target":"region","label":"регион"})
    if p.get("tz"):
        nodes.append({"id":"tz","label":p["tz"],"type":"timezone",
                      "icon":"globe","color":"#8B5CF6","sub":"часовой пояс"})
        edges.append({"source":root_id,"target":"tz","label":"часовой пояс"})
    for r in check_phone_services(p["digits"]):
        nid = f"svc_{r['id']}"
        nodes.append({"id":nid,"label":r["name"],"type":"platform",
                      "icon":r["icon"],"color":r["color"],"sub":r.get("sub",""),
                      "status":r["status"],"url":r["url"],
                      "username":p["digits"],"reliable":r["reliable"]})
        edges.append({"source":root_id,"target":nid,"label":r["status"]})
    return {"phone":p,"nodes":nodes,"edges":edges}

def build_username_graph(username):
    username = username.strip().lstrip("@")
    if not username or len(username) < 2: return {"error":"невалидный username"}
    if not re.match(r"^[a-zA-Z0-9._\-]+$", username): return {"error":"только буквы, цифры, . _ -"}
    nodes = []; edges = []
    root_id = "user"
    nodes.append({"id":root_id,"label":"@"+username,"type":"username",
                  "icon":"user","color":"#8b5cf6"})
    for r in check_platforms(username):
        nid = f"user_{r['id']}"
        nodes.append({"id":nid,"label":r["name"],"type":"platform",
                      "icon":r["icon"],"color":r["color"],"sub":r.get("sub","найден"),
                      "status":r["status"],"url":r["url"],
                      "username":username,"reliable":r["reliable"]})
        edges.append({"source":root_id,"target":nid,"label":r["status"]})
    return {"username":username,"nodes":nodes,"edges":edges}

def build_email_graph(raw_email):
    email = raw_email.strip().lower()
    if not EMAIL_RE.match(email): return {"error":"невалидный email"}
    login, domain = email.split("@",1)
    tld = domain.rsplit(".",1)[-1]
    md5 = hashlib.md5(email.encode()).hexdigest()
    nodes = []; edges = []
    root_id = "email"
    nodes.append({"id":root_id,"label":email,"type":"email","icon":"mail","color":"#8b5cf6"})
    nodes.append({"id":"login","label":"@"+login,"type":"login","icon":"user",
                  "color":"#3B82F6","sub":"логин"})
    edges.append({"source":root_id,"target":"login","label":"логин"})
    nodes.append({"id":"domain","label":domain,"type":"domain","icon":"globe",
                  "color":"#10B981","sub":f"TLD .{tld}"})
    edges.append({"source":root_id,"target":"domain","label":"домен"})
    nodes.append({"id":"md5","label":md5[:16]+"…","type":"hash","icon":"lock",
                  "color":"#6366f1","sub":"Gravatar MD5"})
    edges.append({"source":root_id,"target":"md5","label":"MD5"})
    for r in check_email_services(email):
        nid = f"svc_{r['id']}"
        nodes.append({"id":nid,"label":r["name"],"type":"platform",
                      "icon":r["icon"],"color":r["color"],"sub":r.get("sub",""),
                      "status":r["status"],"url":r["url"],
                      "username":login,"reliable":r["reliable"]})
        edges.append({"source":root_id,"target":nid,"label":r["status"]})
    return {"email":email,"username":login,"domain":domain,
            "nodes":nodes,"edges":edges}

# ==================== SERVER ====================
def load_index():
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, "index.html"), "r", encoding="utf-8") as f:
        return f.read()

class Handler(BaseHTTPRequestHandler):
    def _send(self, body, ctype="text/html", code=200):
        if isinstance(body, str): body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            try: return self._send(load_index())
            except Exception as e: return self._send(f"index.html not found: {e}", "text/plain", 500)
        if u.path == "/api/check":
            qs = parse_qs(u.query)
            phone = qs.get("phone", [""])[0]
            if not phone: return self._send(json.dumps({"error":"нет номера"}), "application/json")
            try: data = build_graph(phone)
            except Exception as e: data = {"error": str(e)}
            return self._send(json.dumps(data, ensure_ascii=False), "application/json")
        if u.path == "/api/username":
            qs = parse_qs(u.query)
            uname = qs.get("u", [""])[0]
            if not uname: return self._send(json.dumps({"error":"нет username"}), "application/json")
            try: data = build_username_graph(uname)
            except Exception as e: data = {"error": str(e)}
            return self._send(json.dumps(data, ensure_ascii=False), "application/json")
        if u.path == "/api/email":
            qs = parse_qs(u.query)
            email = qs.get("e", [""])[0]
            if not email: return self._send(json.dumps({"error":"нет email"}), "application/json")
            try: data = build_email_graph(email)
            except Exception as e: data = {"error": str(e)}
            return self._send(json.dumps(data, ensure_ascii=False), "application/json")
        self._send("Not found", "text/plain", 404)

    def log_message(self, *a): pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"🌐 http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
