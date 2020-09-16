import requests
from bs4 import BeautifulSoup

def get_row(table_rows, product, vuln_id, tr):
    # 한개의 row 를 각각의 열로 쪼갬
    td = table_rows[tr].find_all('td')

    summary = td[0].find('p').text
    published = td[0].find('span').text

    cvss_severity = []
    cvss_severity_tmp = td[1].find_all('span')

    for c in cvss_severity_tmp:
        try:
            c_version = c.find('em').text.strip()
            c_content = c.find('a').text.strip()
            cvss_severity.append(c_version + ' ' + c_content)
        except AttributeError:
            cvss_severity.append('(not available)')

    # 결과 데이터에 들어갈 row(list)
    return [product, vuln_id, cvss_severity, published, summary]


def get_page_indexes(url_cve):
    req = requests.get(url_cve)
    html = req.text
    soup = BeautifulSoup(html, 'html5lib')

    # page index get
    try:
        cve_page_indexes = int(
            soup.select(".pagination > li > a")[-1].attrs['href'].split('&')[-1].split('=')[-1]) // 20
    except IndexError:
        cve_page_indexes = 1

    return cve_page_indexes