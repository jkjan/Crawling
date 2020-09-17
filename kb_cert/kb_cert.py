# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from utils import save

def kb_cert(path):
    # 표 컬럼 목록
    cols = ['Product', 'Scope', 'Impact', 'Likelihood', 'Description', 'CWE Description', 'CWE Extended Description']

    # 정렬할 기준
    standard = ['Product', 'Scope', 'Impact']

    # 저장 파일 및 위치
    save_file = path + 'result_kb_cert.csv'

    # 조사할 product 목록
    products = [
        'Tizen', 'windows 10'
    ]

    # 조사할 product hash key
    vuln_ids = {
        'Tizen': '240311',
        'windows 10': '576688'
    }

    basic_url = 'https://kb.cert.org/vuls/id/'

    # 최종 데이터
    res = []

    for product in products:
        vuln_id = vuln_ids[product]
        url_tmp = basic_url + vuln_id
        print(url_tmp)

        # url get (page 번호 얻기용)
        req = requests.get(url_tmp)

        # html parser
        html = req.text
        soup = BeautifulSoup(html, 'html.parser')

        description = soup.select('table.wrapper-table > tr > td > p')[0].text
        print(description)

        links = soup.select('table.wrapper-table > tr > td > p > a')

        for link in links:
            link = link['href']
            if 'cwe' in link:
                # url get (page 번호 얻기용)
                print(link)
                req = requests.get(link)

                # html parser
                html = req.text
                soup = BeautifulSoup(html, 'html5lib')

                cwe_description = soup.select('#Description > div.expandblock > div.detail > div.indent')[0].text
                try:
                    cwe_extended_description = soup.select('#Extended_Description > '
                                                           'div.expandblock > '
                                                           'div.detail > '
                                                           'div.indent')[0].text
                except IndexError:
                    cwe_extended_description = ''

                table = soup.select('#Common_Consequences > '
                                    'div.expandblock > '
                                    'div.tabledetail > '
                                    'div.indent > '
                                    '#Detail')[0]

                table_rows = table.find_all('tr')

                for tr in range(1, len(table_rows)):
                    tds = table_rows[tr].find_all('td')

                    scope = tds[0].text.strip()

                    impact_tmp = tds[1].select('div')

                    impact_tech = impact_tmp[0].text.strip()
                    impact_content = impact_tmp[1].text.strip()

                    likelihood = tds[2].text.strip()

                    row = [product, scope, impact_tech + '\n' +
                           impact_content, likelihood, cwe_description,
                           cwe_extended_description, description]
                    res.append(row)


    save(res, cols, standard, save_file)
