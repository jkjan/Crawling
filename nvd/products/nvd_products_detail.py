# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from utils import save
from nvd.nvd_modules import get_row


def nvd_products_detail(path):
    # 표 컬럼 목록
    cols = ["Product", "Vuln ID", "CVSS Severity", "Published", "Summary"]

    # 정렬할 기준
    standard = ['Product', 'Vuln ID']

    # 저장 파일 및 위치
    save_file = path + 'result_smu_nvd_products_detail.csv'

    # 기본 url
    basic_url_front = 'https://nvd.nist.gov/products/cpe/detail/'
    basic_url_rear = '?status=FINAL&orderBy=CPEURI&namingFormat=2.3'

    products = [
        'android wear', 'brillo', 'Tizen1', 'Tizen2'
    ]

    # 조사할 product 목록
    detail_nums = {
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

    for product in products:
        detail_num = detail_nums[product]
        keyword = keywords[product]
        url_tmp = basic_url_front + detail_num + basic_url_rear + keyword
        print(url_tmp)

        # url get (page 번호 얻기용)
        req = requests.get(url_tmp)

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

        # table 의 열 크롤링
        for tr in range(len(table_rows)):

            vuln_id = table_rows[tr].find('a').text

            year_check = int(vuln_id.split('-')[1])

            if year_check < 2000:
                continue

            # 결과 데이터에 들어갈 row(list)
            row = get_row(table_rows, product, vuln_id, tr)
            res.append(row)

    save(res, cols, standard, save_file)
