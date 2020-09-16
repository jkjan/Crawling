# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from utils import save
from nvd.nvd_modules import get_row, get_page_indexes


def nvd_products_search(path):
    # 표 컬럼 목록
    cols = ["Product", "Vuln ID", "CVSS Severity", "Published", "Summary"]

    # 정렬할 기준
    standard = ["Product", 'Vuln ID']

    # 저장 파일 및 위치
    save_file = path + 'result_smu_nvd_products_search.csv'

    # 기본 url
    basic_url = 'https://nvd.nist.gov/products/cpe/search/results?status=FINAL&orderBy=CPEURI&namingFormat=2.3'

    products = [
        'Zephyr', 'Watch OS', 'Vxworks'
    ]

    # 조사할 vendor id 목록
    keywords = {
        'Zephyr': '&keyword=Zephyr',
        'Watch OS': '&keyword=watch+os',
        'Vxworks': '&keyword=vxworks'
    }

    # 최종 데이터
    res = []

    for product in products:
        keyword = keywords[product]

        url_tmp = basic_url + keyword

        page_indexes = get_page_indexes(url_tmp)

        # 위에서 얻은 page 번호 만큼 반복
        for page_index in range(page_indexes+1):
            url = url_tmp + '&startIndex=' + str(page_index * 20)
            print(url)

            # html parser
            req = requests.get(url)
            html = req.text
            soup = BeautifulSoup(html, 'html5lib')

            url_trs = soup.select('div.searchResults > table > tbody > tr')

            for urlTr in url_trs:
                url_cve = "https://nvd.nist.gov" + urlTr.select('td > div > div > a')[0]['href']
                cve_page_indexes = get_page_indexes(url_cve)

                for cve_page_index in range(cve_page_indexes):
                    cve_url = url_cve + '&startIndex=' + str(cve_page_index * 20)
                    print(cve_url)

                    req = requests.get(url_cve)
                    html = req.text
                    soup = BeautifulSoup(html, 'html5lib')

                    # 크롤링할 table get
                    table = soup.find('tbody')

                    # row 단위로 쪼갬
                    try:
                        table_rows = table.find_all('tr')
                    except AttributeError:
                        continue

                    year_in_range = False

                    # table 의 열 크롤링
                    for tr in range(len(table_rows)):

                        vuln_id = table_rows[tr].find('a').text

                        year_check = int(vuln_id.split('-')[1])

                        if year_check >= 2015:
                            year_in_range = True
                        else:
                            continue

                        # 결과 데이터에 들어갈 row(list)
                        row = get_row(table_rows, product, vuln_id, tr)

                        if row not in res:
                            res.append(row)

                    if not year_in_range:
                        print('page %d is break' % page_index)
                        break

    save(res, cols, standard, save_file)