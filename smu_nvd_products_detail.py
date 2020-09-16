# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from googletrans import Translator
from save_to_csv import save

def nvd_products_detail(path):
    # 표 컬럼 목록
    cols = ["Product","Vuln ID", "CVSS Serverity", "Published", "Summary"]

    # 정렬할 기준
    standard = ['Product','Vuln ID']

    # 저장 파일 및 위치
    saveFile = path + 'result_smu_nvd_products_detail.csv'

    # 기본 url
    basicUrlFront = 'https://nvd.nist.gov/products/cpe/detail/'
    basicUrlRear = '?status=FINAL&orderBy=CPEURI&namingFormat=2.3'

    products = [
        'android wear', 'brillo', 'Tizen1', 'Tizen2'
    ]

    # 조사할 product 목록
    detailNums = {
        'android wear': '289933', 'brillo': '290105', 'Tizen1': '195579', 'Tizen2': '195580'
    }

    # 조사할 vendor id 목록
    keywords = {
        'android wear': '&keyword=android+wear',
        'brillo': '&keyword=brillo',
        'Tizen1': '&keyword=tizen',
        'Tizen2': '&keyword=tizen'
    }

    # 최종 데이터
    res = []
    row=[]
    for product in products:
        detailNum = detailNums[product]
        # 조사할 product id, vendor id, sha, year, trc

        keyword = keywords[product]

        urlTmp = basicUrlFront + detailNum + basicUrlRear + keyword
        print(urlTmp)

        # url get (page 번호 얻기용)
        req = requests.get(urlTmp)

        # html parser
        html = req.text
        soup = BeautifulSoup(html, 'html5lib')

        # page index get
        url = 'http://nvd.nist.gov' + soup.select('#body-section > div > div > div.row > a')[0]['href']
        print(url)

        # html parser
        req = requests.get(url)
        html = req.text
        soup = BeautifulSoup(html, 'html5lib')

        # 크롤링할 table get
        table = soup.find('tbody')

        # row 단위로 쪼갬
        try:
            table_rows = table.find_all('tr')
        except AttributeError:
            continue

        yearInRange = False

        # table의 열 크롤링
        for tr in range(len(table_rows)):

            vulnId = table_rows[tr].find('a').text

            yearCheck = int(vulnId.split('-')[1])

            if yearCheck >= 2000:
                yearInRange = True
            else:
                continue

            # 한개의 row를 각각의 열로 쪼갬
            td = table_rows[tr].find_all('td')

            summary = td[0].find('p').text
            published = td[0].find('span').text

            cvssSeverity = []
            cvssSeverityTmp = td[1].find_all('span')

            for c in cvssSeverityTmp:
                try:
                    cVersion = c.find('em').text.strip()
                    cContent = c.find('a').text.strip()
                    cvssSeverity.append(cVersion + ' ' + cContent)
                except AttributeError:
                    cvssSeverity.append('(not available)')

            # 결과 데이터에 들어갈 row(list)
            row = [product,vulnId, cvssSeverity, published, summary]

            # 해석된 description row에 저장
            # try:
            #     row.append(translator.translate(summary, src='en', dest='ko').text)
            # except:
            #     row.append('translator err')

            res.append(row)

    save(res, cols, standard, saveFile)
