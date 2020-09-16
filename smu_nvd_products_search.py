# 필수 설치 plugin
# pandas, requests, beautifulSoup4, googletrans
import pandas as pd
import requests
from bs4 import BeautifulSoup
from googletrans import Translator
from save_to_csv import save

def nvd_products_search(path):
    # 표 컬럼 목록
    cols = ["Product", "Vuln ID", "CVSS Serverity", "Published", "Summary"]

    # 정렬할 기준
    standard = ["Product", 'Vuln ID']

    # 저장 파일 및 위치
    saveFile = path + 'result_smu_nvd_products_search.csv'

    # 기본 url
    basicUrl = 'https://nvd.nist.gov/products/cpe/search/results?status=FINAL&orderBy=CPEURI&namingFormat=2.3'

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
    row=[]
    for product in products:
        keyword = keywords[product]

        urlTmp = basicUrl + keyword
        print(urlTmp)

        # url get (page 번호 얻기용)
        req = requests.get(urlTmp)

        # html parser
        html = req.text
        soup = BeautifulSoup(html, 'html5lib')

        # page index get
        try:
            pageIndexes = int(soup.select(".pagination > li > a")[-1].attrs['href'].split('&')[-1].split('=')[-1]) // 20
        except IndexError:
            pageIndexes = 1

        # 위에서 얻은 page 번호 만큼 반복
        for pageIndex in range(pageIndexes+1):
            url = urlTmp + '&startIndex=' + str(pageIndex * 20)
            print(url)

            # html parser
            req = requests.get(url)
            html = req.text
            soup = BeautifulSoup(html, 'html5lib')

            urlTrs = soup.select('div.searchResults > table > tbody > tr')
            for urlTr in urlTrs:
                urlCve = "https://nvd.nist.gov" + urlTr.select('td > div > div > a')[0]['href']
                print(urlCve)
                # html parser
                req = requests.get(urlCve)
                html = req.text
                soup = BeautifulSoup(html, 'html5lib')

                # page index get
                try:
                    cvePageIndexes = int(
                        soup.select(".pagination > li > a")[-1].attrs['href'].split('&')[-1].split('=')[-1]) // 20
                except IndexError:
                    cvePageIndexes = 1

                for cvePageIndexe in range(cvePageIndexes):
                    cveUrl = urlCve + '&startIndex=' + str(cvePageIndexe * 20)
                    print(cveUrl)

                    req = requests.get(urlCve)
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

                        if yearCheck >= 2015:
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
                        row = [product, vulnId, cvssSeverity, published, summary]

                        # 해석된 description row에 저장
                        # try:
                        #     row.append(translator.translate(summary, src='en', dest='ko').text)
                        # except:
                        #     row.append('translator err')
                        if row not in res:
                            res.append(row)
                    if not yearInRange:
                        print('page %d is break' % pageIndex)
                        break

    save(res, cols, standard, saveFile)