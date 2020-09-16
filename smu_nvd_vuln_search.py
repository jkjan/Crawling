# 필수 설치 plugin
import requests
from bs4 import BeautifulSoup
from save_to_csv import save

def nvd_vuln_search(path):
    # 표 컬럼 목록
    cols = ["구분", "Vendor", "제품 이름", "Vuln ID", "CVSS Serverity", "Published", "Summary"]

    # 정렬할 기준
    standard = ['구분', 'Vendor','제품 이름']

    # 저장 파일 및 위치
    saveFile = path + 'result_smu_nvd_vuln_search.csv'

    # 기본 url
    basicUrl = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all'

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
    querys = {
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
    row=[]
    for product in products:
        # 조사할 product id, vendor id, sha, year, trc
        query = querys[product]
        cpe_vendor = cpe_vendors[product]

        productTmp = product.split('|')

        division = productTmp[0]
        vendor = productTmp[1]
        productName = productTmp[2]

        urlTmp = basicUrl + query + cpe_vendor

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
        for pageIndex in range(pageIndexes):
            url = urlTmp + '&startIndex=' + str(pageIndex * 20)
            print(url)

            # html parser
            req = requests.get(url)
            html = req.text
            soup = BeautifulSoup(html, 'html5lib')

            # 크롤링할 table get
            table = soup.find('tbody')

            # row 단위로 쪼갬
            table_rows = table.find_all('tr')

            yearInRange = False

            # table의 열 크롤링
            for tr in range(len(table_rows)):

                vulnId = table_rows[tr].find('a').text

                yearCheck = int(vulnId.split('-')[1])

                if yearCheck >= 2018:
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
                row = [division, vendor, productName, vulnId, cvssSeverity, published, summary]

                # # 해석된 description row에 저장
                # try:
                #     row.append(translator.translate(summary, src='en', dest='ko').text)
                # except:
                #     row.append('translator err')

                res.append(row)
                print(row)

            if not yearInRange:
                print('page %d is break' % pageIndex)
                break


    save(res, cols, standard, saveFile)

