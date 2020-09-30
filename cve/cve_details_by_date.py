import calendar
from utils import save, get_soup, get_text
from cve.meta_data import cols, standard


base_url = "https://www.cvedetails.com"


def get_vuln_data(rows):
    vuln_data = []

    # 힌 행의 데이터 가져오기
    for i in range(0, len(rows)):
        if i == 4:
            vuln_data.append(vuln_data[i-2] + ' ' + vuln_data[i-1])
        refined = get_text(rows[i])
        vuln_data.append(refined)

    return vuln_data


def get_detail_data(cve_id):
    detail_url = base_url + "/cve/" + cve_id
    detail_data = []

    # 테이블 가져오기
    detail_soup = get_soup(detail_url)
    detail_table = detail_soup.select('table#vulnprodstable > tbody > tr')[1:]

    # 취약점 정보가 없을 경우
    try:
        div = detail_table[0].select('td > div')[0]
        if div.get('class')[0] == 'errormsg':
            return None
    except IndexError:
        pass

    # 행 별로 취약점 정보 가져오기
    for detail_table_elem in detail_table:
        rows = detail_table_elem.find_all('td')[1:-1]
        vuln_data = get_vuln_data(rows)
        detail_data.append(vuln_data)

    return detail_data


def get_cve_data(rows, desc):
    cve_metadata = []

    # 한 행의 데이터 가져오기
    for data in rows:
        refined = get_text(data)
        cve_metadata.append(refined)

    # 행 밑의 설명 추가하기
    description = desc.find('td')
    refined = get_text(description)
    cve_metadata.append(refined)

    cve_id = cve_metadata[0]
    detail_data = get_detail_data(cve_id)

    cve_data = []
    if detail_data is None:
        cve_data.append(['' for i in range(8)] + cve_metadata)
    else:
        for d in detail_data:
            cve_data.append(d + cve_metadata)

    return cve_data


def get_page_data(page_url):
    page_soup = get_soup(page_url)
    cve_table = page_soup.select('table#vulnslisttable > tbody > tr')[1:]
    page_data = []

    for cve_index in range(0, len(cve_table), 2):
        rows = cve_table[cve_index].find_all('td')[1:]
        cve_data = get_cve_data(rows, cve_table[cve_index + 1])
        page_data += cve_data

    return page_data


def get_month_data(year_url, month):
    print(calendar.month_name[month])
    list_url = year_url + "month-" + str(month) + "/" + calendar.month_name[month] + ".html"
    list_soup = get_soup(list_url)
    pages = list_soup.select("div.paging > a")

    month_data = []

    for page_index in range(len(pages)):
        print("page", page_index + 1)
        page_url = base_url + pages[page_index].get("href")
        month_data += get_page_data(page_url)

    return month_data


def get_year_data(path, year):
    print(year)
    year_url = base_url + "/vulnerability-list/year-" + year + "/"
    year_data = []

    for month in range(1, 13):
        try:
            month_data = get_month_data(year_url, month)
            if month_data is not None:
                year_data += month_data
            print()
        except KeyboardInterrupt:
            break

    if len(year_data) != 0:
        file_name = "cve_details_" + str(year) + ".csv"
        save(year_data, cols, standard, path + file_name)
        print("year " + year + " saved")


def get_years():
    years_url = base_url + "/browse-by-date.php"
    print(years_url)
    years_soup = get_soup(years_url)
    year_table = years_soup.select('table.stats > tbody')[0]
    rows = year_table.find_all('tr')[1:]
    years = []
    for row in rows:
        year = get_text(row.select('th > a')[0])
        num = get_text(row.find('td'))
        if num != '':
            years.append(year)
    return years


def cve_details(path):
    years = get_years()
    for year in years:
        get_year_data(path, year)
