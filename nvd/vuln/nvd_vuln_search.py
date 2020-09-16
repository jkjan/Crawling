# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from utils import save
from nvd.nvd_modules import get_page_indexes, get_row


def nvd_vuln_search(path):
    # 표 컬럼 목록
    cols = ["구분", "Vendor", "제품 이름", "Vuln ID", "CVSS Severity", "Published", "Summary"]

    # 정렬할 기준
    standard = ['구분', 'Vendor', '제품 이름']

    # 저장 파일 및 위치
    save_file = path + 'result_smu_nvd_vuln_search.csv'

    # 기본 url
    basic_url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all'

    # 조사할 product 목록
    products = [
        'embedded linux|Linux|제품총합',
        'embedded linux|Linux|Audit',
        'embedded linux|Linux|Direct Connect',
        'embedded linux|Linux|Ipsec Tools Racoon Daemon',
        'embedded linux|Linux|Kernel',
        'embedded linux|Linux|Systemd',
        'embedded linux|Linux|Util-linux',
        'AI 스피커|Amazon|echo',
        'AI 스피커|Apple|siri',
        '기타|Microsoft|cortana'
    ]

    # 조사할 vendor id 목록
    queries = {
        'embedded linux|Linux|제품총합': '&query=linux',
        'embedded linux|Linux|Audit': '&query=audit',
        'embedded linux|Linux|Direct Connect': '&query=Direct+Connect',
        'embedded linux|Linux|Ipsec Tools Racoon Daemon': '&query=Ipsec+Tools+Racoon+Daemon',
        'embedded linux|Linux|Kernel': '&query=Kernel',
        'embedded linux|Linux|Systemd': '&query=Systemd',
        'embedded linux|Linux|Util-linux': '&query=Util-linux',
        'AI 스피커|Amazon|echo': '&query=echo',
        'AI 스피커|Apple|siri': '&query=siri',
        '기타|Microsoft|cortana': '&query=cortana'
    }

    cpe_vendors = {
        'embedded linux|Linux|제품총합': '&cpe_vendor=cpe%3A%2F%3Alinux',
        'embedded linux|Linux|Audit': '&cpe_vendor=cpe%3A%2F%3Alinux',
        'embedded linux|Linux|Direct Connect': '&cpe_vendor=cpe%3A%2F%3Alinux',
        'embedded linux|Linux|Ipsec Tools Racoon Daemon': '&cpe_vendor=cpe%3A%2F%3Alinux',
        'embedded linux|Linux|Kernel': '&cpe_vendor=cpe%3A%2F%3Alinux',
        'embedded linux|Linux|Systemd': '&cpe_vendor=cpe%3A%2F%3Alinux',
        'embedded linux|Linux|Util-linux': '&cpe_vendor=cpe%3A%2F%3Alinux',
        'AI 스피커|Amazon|echo': '&cpe_vendor=cpe%3A%2F%3Aamazon',
        'AI 스피커|Apple|siri': '&cpe_vendor=cpe%3A%2F%3Aapple',
        '기타|Microsoft|cortana': '&cpe_vendor=cpe%3A%2F%3Amicrosoft'
    }

    # 최종 데이터
    res = []

    for product in products:
        # 조사할 product id, vendor id, sha, year, trc
        query = queries[product]
        cpe_vendor = cpe_vendors[product]

        product_tmp = product.split('|')

        division = product_tmp[0]
        vendor = product_tmp[1]
        product_name = product_tmp[2]

        url_tmp = basic_url + query + cpe_vendor

        # url get (page 번호 얻기용)
        page_indexes = get_page_indexes(url_tmp)

        # 위에서 얻은 page 번호 만큼 반복
        for pageIndex in range(page_indexes):
            url = url_tmp + '&startIndex=' + str(pageIndex * 20)
            print(url)

            # html parser
            req = requests.get(url)
            html = req.text
            soup = BeautifulSoup(html, 'html5lib')

            # 크롤링할 table get
            table = soup.find('tbody')

            # row 단위로 쪼갬
            table_rows = table.find_all('tr')

            year_in_range = False

            # table 의 열 크롤링
            for tr in range(len(table_rows)):

                vuln_id = table_rows[tr].find('a').text

                year_check = int(vuln_id.split('-')[1])

                if year_check >= 2018:
                    year_in_range = True
                else:
                    continue

                # 결과 데이터에 들어갈 row(list)
                row = get_row(table_rows, product, vuln_id, tr)
                row = [division, vendor, product_name] + row

                res.append(row)
                print(row)

            if not year_in_range:
                print('page %d is break' % pageIndex)
                break


    save(res, cols, standard, save_file)
