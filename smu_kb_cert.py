# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from save_to_csv import save

def kb_cert(path):
    # 표 컬럼 목록
    cols = ['Product','Scope', 'Impact', 'Likelihood', 'Description', 'CWE Description', 'CWE Extended Description']

    # 정렬할 기준
    standard = ['Product','Scope', 'Impact']

    # 저장 파일 및 위치
    saveFile = path + 'result_smu_kb_cert.csv'

    # 조사할 product 목록
    products = [
        'Tizen', 'windows 10'
    ]

    # 조사할 product hash key
    vulsIds = {
        'Tizen': '240311',
        'windows 10': '576688'
    }

    basicUrl = 'https://kb.cert.org/vuls/id/'

    # 최종 데이터
    res = []

    for product in products:
        vulsId = vulsIds[product]
        urlTmp = basicUrl + vulsId
        print(urlTmp)

        # url get (page 번호 얻기용)
        req = requests.get(urlTmp)

        # html parser
        html = req.text
        soup = BeautifulSoup(html, 'html5lib')

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

                cweDescription = soup.select('#Description > div.expandblock > div.detail > div.indent')[0].text
                try:
                    cweExtendedDescription = \
                    soup.select('#Extended_Description > div.expandblock > div.detail > div.indent')[0].text
                except IndexError:
                    cweExtendedDescription = ''

                table = soup.select('#Common_Consequences > div.expandblock > div.tabledetail > div.indent > #Detail')[0]

                table_rows = table.find_all('tr')

                for tr in range(1, len(table_rows)):
                    tds = table_rows[tr].find_all('td')

                    scope = tds[0].text.strip()

                    impactTmp = tds[1].select('div')

                    impactTech = impactTmp[0].text.strip()
                    impactContent = impactTmp[1].text.strip()

                    likelihood = tds[2].text.strip()

                    row = [product, scope, impactTech + '\n' + impactContent, likelihood, cweDescription, cweExtendedDescription,
                           description]
                    res.append(row)


    save(res, cols, standard, saveFile)
