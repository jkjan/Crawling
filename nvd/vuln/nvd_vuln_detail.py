# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from utils import save

def nvd_vuln_detail(path):
    # 표 컬럼 목록
    cols = ["구분", "Vendor", "제품 이름", "CVE", "Base Score", "Access Vector (AV)", "Access Complexity (AC)",
            "Authentication (AU)", "Confidentiality (C)", "Integrity (I)", "Availability (A)", "Description"]

    # 정렬할 기준
    standard = ["구분", "Vendor", ]

    # 저장 파일 및 위치
    save_file = path + 'result_nvd_vuln_detail.csv'

    # 기본 url
    basic_url = 'https://nvd.nist.gov/vuln/detail/'

    # 조사할 product 목록
    products = [
        '기타|Amazon|Alexa',
        'AI 스피커|Google|Google Home',
        'AI 스피커|Lenovo|Lenovo Smart Assistant',
        '기타|Google|Google Assistant'
    ]

    # 조사할 vendor id 목록
    cves = {
        '기타|Amazon|Alexa': 'CVE-2018-11567',
        'AI 스피커|Google|Google Home': 'CVE-2018-12716',
        'AI 스피커|Lenovo|Lenovo Smart Assistant': 'CVE-2018-9070#vulnCurrentDescriptionTitle',
        '기타|Google|Google Assistant': 'CVE-2019-2103'
    }

    # 최종 데이터
    res = []

    for product in products:
        # 조사할 product id, vendor id, sha, year, trc
        cve = cves[product]
        product_tmp = product.split('|')
        division = product_tmp[0]
        vendor = product_tmp[1]
        product_name = product_tmp[2]

        url = basic_url + cve
        print(url)

        # html parser
        req = requests.get(url)
        html = req.text
        soup = BeautifulSoup(html, 'html5lib')

        # 크롤링할 table get
        base_score = soup.select("span.severityDetail > a")[0].text.strip()
        print(base_score)

        cvss2 = soup.find("span", attrs={"data-testid": "vuln-cvss2-panel-vector"}).text.strip()
        cvss3 = soup.find("span", attrs={"data-testid": "vuln-cvss3-nist-vector"}).text.strip()
        description = soup.select("span#cvss2FootNoteSection > i")[0].text.strip()
        cvss2 = cvss2[1:-1].split("/")
        cvss3 = cvss3.split("/")
        access_vector = cvss2[0][-1]
        access_complexity = cvss2[1][-1]
        authentication = cvss2[2][-1]
        availability = cvss2[-1][-1]
        integrity = cvss2[-2][-1]
        confidentiality = cvss3[-3][-1]

        # 결과 데이터에 들어갈 row(list)
        row = [division, vendor, product_name, cve, base_score, access_vector, access_complexity, authentication,
               confidentiality, integrity, availability, description]

        res.append(row)

    save(res, cols, standard, save_file)
