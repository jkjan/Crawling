import requests
from bs4 import BeautifulSoup
from utils import save
from cve.meta_data import product_ids, vendor_ids, shas, years, trcs, cols, standard


def smu_cve_details(err, path, num, products):
    save_file = path + 'result_smu_cve_details_' + str(num) + '.csv'
    # 최종 데이터
    res = []

    for product in products:
        # 조사할 product id, vendor id, sha, year, trc
        product_id = str(product_ids[product])
        vendor_id = str(vendor_ids[product])
        sha = shas[product]
        year = years[product]
        trc = trcs[product]

        # url get (page 번호 얻기용)
        req = requests.get('https://www.cve_details.com/vulnerability-list/vendor_id-' + str(vendor_id)
                           + '/product_id-' + str(product_id)
                           + '/year-' + str(year)
                           + '/' + product + '.html')

        # html parser
        html = req.text
        soup = BeautifulSoup(html, 'html5lib')

        # page 번호 get
        page_num = len(soup.select('div.paging > a'))

        # 위에서 얻은 page 번호 만큼 반복
        for page in range(1, page_num + 1):
            # url get (분석용)
            url = 'https://www.cve_details.com/vulnerability-list.php?' \
                  'vendor_id=' + vendor_id + \
                  '&product_id=' + product_id + \
                  '&version_id=&page=' + str(page) + \
                  '&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0' \
                  '&year=' + str(year) + \
                  '&month=0&cweid=0&order=1' \
                  '&trc=' + str(trc) + sha
            print(url)

            # html parser
            req = requests.get(url)
            html = req.text
            soup = BeautifulSoup(html, 'html5lib')

            # 크롤링할 table get
            table = soup.find('table', attrs='searchresults sortable')

            # row 단위로 쪼갬
            table_rows = table.find_all('tr')

            # 첫번째 줄은 헤더이므로 pass 따라서 시작은 1부터 (코드 상단에 cols 으로 헤더 정의)
            for tr in range(1, len(table_rows), 2):

                # 한개의 row 를 각각의 열로 쪼갬
                td = table_rows[tr].find_all('td')

                # 결과 데이터에 들어갈 row(list)
                row = []

                # table 크롤링 결과를 row 에 저장
                for i in range(1, len(td)):
                    if i == 5:
                        row.append(row[2] + " " + row[3])
                    else:
                        row.append(td[i].text.strip().replace('\t', ''))

                # description get
                description = table_rows[tr + 1].text.strip()

                # description row 에 저장
                row.append(description)

                # 상세정보 url get
                cve_url = 'https://www.cve_details.com/cve/' + row[0] + '/'

                # 상세정보 url parser
                req2 = requests.get(cve_url)
                html2 = req2.text
                soup2 = BeautifulSoup(html2, 'html5lib')

                # 상세정보 url 에서 table get
                table2 = soup2.find("table", id="vulnprodstable")

                # get 한 테이블을 row 로 쪼갬
                try:
                    table_rows2 = table2.find_all('tr')
                except AttributeError:
                    print(cve_url)
                    err.write(cve_url + "\n")
                    continue

                # 상세정보 url 정보를 저장할 row 생성
                # 각 row 만큼 반복 (첫 번째는 헤더이므로 시작은 1부터)
                for tr2 in range(1, len(table_rows2)):

                    # 각 row 를 컬럼으로 쪼갬
                    td2 = table_rows2[tr2].find_all('td')

                    row2 = []
                    # 각 row 의 컬럼 데이터 row2에 저장
                    for i in range(1, len(td2) - 1):
                        row2.append(td2[i].text.strip().replace('\t', ''))

                    # 상세정보 url row2 데이터와 상위 url row 데이터가 존재하면 최종데이터(res)에 저장
                    if row and row2:
                        res.append(row2 + row)


    save(res, cols, standard, save_file)
