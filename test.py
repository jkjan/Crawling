from bs4 import BeautifulSoup
import requests

"""
https://www.cvedetails.com/cve/CVE-2019-1368/
https://www.cvedetails.com/cve/CVE-2019-1294/
https://www.cvedetails.com/cve/CVE-2019-0888/
https://www.cvedetails.com/cve/CVE-2019-1368/
https://www.cvedetails.com/cve/CVE-2019-1294/
"""

err = open("error/error.txt", "rt")

i = 0
while True:
    i += 1
    url = err.readline()
    if len(url) == 0:
        break
    url = url[:-1]
    print("url:", url)
    src = requests.get(url).text
    bs = BeautifulSoup(src, 'html5lib')
    table2 = bs.find("table", id="vulnprodstable")
    table_rows2 = table2.find_all('tr')

    # 상세정보 url 정보를 저장할 row 생성
    # 각 row만큼 반복 (첫 번째는 헤더이므로 시작은 1부터)
    for tr2 in range(1, len(table_rows2)):
        # 각 row를 컬럼으로 쪼갬
        td2 = table_rows2[tr2].find_all('td')

        row2 = []
        # 각 row의 컬럼 데이터 row2에 저장
        for i in range(1, len(td2) - 1):
            row2.append(td2[i].text.strip().replace('\t', ''))

        # 상세정보 url row2 데이터와 상위 url row 데이터가 존재하면 최종데이터(res)에 저장
        print(row2)