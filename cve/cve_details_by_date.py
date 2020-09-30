import calendar
from utils import save, get_soup, get_text, append_to
from cve.meta_data import cols, standard


# 기본 주소
base_url = "https://www.cvedetails.com"

# 태그 위치
tag_pos = {
    # 전체 연도 화면에 있는 연도들
    'year_table': 'table.stats > tbody',

    # 월별 화면에서 페이지들
    'pages': 'div.paging > a',

    # 월별 취약점 수
    'total_number': 'div.paging > b',

    # 한 페이지에 있는 CVE 들
    'cves': 'table#vulnslisttable > tbody > tr',

    # CVE ID 에 영향받는 제품들
    'products_table': 'table#vulnprodstable > tbody > tr',

    # CVE ID 에 해당하는 제품이 없을 시의 에러 메시지
    'err_msg': 'td > div'
}


# 제품 데이터 하나 가져오기
def get_product_data(rows):
    product_data = []

    for i in range(0, len(rows)):
        # Product Version 데이터 만들기
        if i == 4:
            product_data.append(product_data[i-2] + ' ' + product_data[i-1])
        append_to(product_data, rows[i])

    return product_data


# CVE ID 에 영향 받는 제품 데이터 가져오기
def get_products_data(cve_id):
    products_url = base_url + "/cve/" + cve_id
    products_data = []

    # 제품 테이블 가져오기
    try:
        products_soup = get_soup(products_url)
        products_table = products_soup.select(tag_pos['products_table'])[1:]
    except (IndexError, AttributeError):
        print("제품 테이블을 가져오지 못하였습니다.")
        raise IndexError

    # 제품 테이블이 없을 경우
    try:
        div = products_table[0].select(tag_pos['err_msg'])[0]
        if div.get('class')[0] == 'errormsg':
            return None
    except IndexError:
        pass

    # 제품 데이터 가져오기
    for elem in products_table:
        rows = elem.find_all('td')[1:-1]
        try:
            vuln_data = get_product_data(rows)
        except (IndexError, AttributeError):
            print(cve_id + "의 제품 데이터 중 일부를 얻지 못하였습니다.")
            raise IndexError

        products_data.append(vuln_data)

    return products_data


# CVE 데이터 가져오기
def get_cve_data(rows, desc):
    cve_data = []

    # CVE 정보 가져오기
    for data in rows:
        append_to(cve_data, data)

    # 설명 추가하기
    description = desc.find('td')
    append_to(cve_data, description)
    
    return cve_data


# CVE 와 그에 영향받는 제품 데이터 가져오기
def get_cve_products_data(row, desc):
    cve_data = get_cve_data(row, desc)

    # CVE ID 로 제품 데이터 가져오기
    try:
        cve_id = cve_data[0]
    except (IndexError, AttributeError):
        # 가져온 CVE 데이터가 없을 경우
        print("CVE 데이터를 얻지 못하였습니다.")
        return None

    try:
        detail_data = get_products_data(cve_id)
    except (IndexError, AttributeError):
        print(cve_id + "의 제품 데이터를 얻지 못하였습니다.")
        return None

    # CVE 정보와 취약점 상세정보 합치기
    cve_products_data = []
    if detail_data is None:
        # 제품 데이터 없었으면 빈 열 추가
        cve_products_data.append(['' for i in range(8)] + cve_data)
    else:
        for d in detail_data:
            cve_products_data.append(d + cve_data)

    return cve_products_data


# 한 페이지 데이터 얻기
def get_page_data(page_index, page_url):
    page_soup = get_soup(page_url)
    cve_table = page_soup.select(tag_pos['cves'])[1:]
    page_data = []

    # 페이지 내의 CVE 데이터 가져오기
    for cve_index in range(0, len(cve_table), 2):
        row = cve_table[cve_index].find_all('td')[1:]
        cve_data = get_cve_products_data(row, cve_table[cve_index + 1])
        if cve_data is None:
            print("오류:", str(page_index) + "페이지 " + str(cve_index//2+1) + "번째 행에 오류가 있습니다.")
            print("주소:", page_url)
            exit(0)

        page_data += cve_data

    return page_data, len(cve_table)//2


# 한 달치 데이터 가져오기
def get_month_data(year, month):
    year_url = base_url + "/vulnerability-list/year-" + year + "/"
    cve_count = 0

    # 페이지별 url 가져오기
    list_url = year_url + "month-" + str(month) + "/" + calendar.month_name[month] + ".html"
    list_soup = get_soup(list_url)
    pages = list_soup.select(tag_pos['pages'])

    # 페이지를 얻을 수 없음
    if len(pages) == 0:
        print("오류:", year + "년 " + str(month) + "월의 페이지 정보를 얻지 못하였습니다.")
        print(list_url)
        exit(0)

    total_number = list_soup.select(tag_pos['total_number'])[0].text
    total_number = int(total_number)

    # 이 달에 보고된 취약점이 없음
    if total_number == 0:
        print(str(month) + "월에는 취약점 데이터가 없습니다.\n")
        return None

    print(str(month) + "월의 취약점 데이터 총 " + str(total_number) + "건을 조사합니다.")
    
    # 페이지별로 데이터 가져오기
    month_data = []
    for page_index in range(len(pages)):
        page_url = base_url + pages[page_index].get("href")
        page_data, cve_per_page = get_page_data(page_index + 1, page_url)
        month_data += page_data
        cve_count += cve_per_page

    if total_number == cve_count:
        print("\t" + str(cve_count) + "건의 취약점 데이터를 성공적으로 얻었습니다.")
    else:
        # 오류는 발생하지 않았으나 수가 맞지 않음
        print("오류: 데이터를 얻는데 확인되지 않은 오류가 발생하였습니다.")
        exit(0)

    return month_data, cve_count


# 1년치 데이터 가져오기
def get_year_data(path, year):
    year_data = []
    cve_count = 0

    print(year[0] + "년도의 취약점 데이터 총 " + year[1] + "건을 조사합니다.")
    for month in range(1, 13):
        month_data, cve_per_month = get_month_data(year[0], month)
        if month_data is not None:
            year_data += month_data
            cve_count += cve_per_month

    if cve_count == int(year[1]):
        print("\n" + str(cve_count) + "건의 취약점 데이터를 성공적으로 얻었습니다.")
    else:
        # 오류는 발생하지 않았으나 수가 맞지 않음
        print("오류: 데이터를 얻는데 확인되지 않은 오류가 발생하였습니다.")
        exit(0)

    file_name = "cve_details_" + year[0] + ".csv"

    try:
        abs_path = path + file_name
        print("해당 데이터를 " + abs_path + " 에 저장합니다.")
        save(year_data, cols, standard, abs_path)
        print("파일 저장에 성공하였습니다.\n")
        file = open("recently_succeeded.txt", "wt")
        file.write(year[0])
        file.close()
    except Exception:
        print("파일 저장에 실패하였습니다.\n")
        print(Exception)
        exit(0)


# 데이터가 있는 연도 데이터 가져오기
def get_years():
    years_url = base_url + "/browse-by-date.php"
    years_soup = get_soup(years_url)
    year_table = years_soup.select(tag_pos['year_table'])[0]
    rows = year_table.find_all('tr')[1:]

    years = []
    for row in rows:
        year = get_text(row.select('th > a')[0])
        num = get_text(row.find('td'))
        if num != '':
            years.append((year, num))
    return years


# CVE 데이터 전체 가져오기
def cve_details(path):
    try:
        years = get_years()
    except (IndexError, AttributeError):
        print("연도별 취약점 수를 얻지 못하였습니다.")
        return

    recently_succeeded = None
    try:
        file = open("recently_succeeded.txt", "rt")
        recently_succeeded = file.read()
        assert len(recently_succeeded) == 4
        print("최근에 " + recently_succeeded + "년까지의 데이터를 성공적으로 모은 기록이 았습니다. 이어서 진행합니다.")
        file.close()
    except (FileNotFoundError, AssertionError):
        pass

    proceed = True

    # 최근 기록 바로 다음 연도부터 시작
    i = 0
    if recently_succeeded is not None:
        while int(years[i][0]) <= int(recently_succeeded) and i < len(years):
            i += 1

    for i in range(i, len(years)):
        if recently_succeeded is not None:
            if int(years[i][0]) <= int(recently_succeeded):
                proceed = False
        if proceed:
            get_year_data(path, years[i])

