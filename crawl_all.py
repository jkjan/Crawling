from cve.cve_details_by_date import cve_details
from kb_cert.kb_cert import kb_cert
from nvd.products.nvd_products_detail import nvd_products_detail
from nvd.products.nvd_products_search import nvd_products_search
from nvd.vuln.nvd_vuln_detail import nvd_vuln_detail
from nvd.vuln.nvd_vuln_search import nvd_vuln_search


# 저장 파일 및 위치
path = 'data/'

try:
    cve_details(path)

    # kb_cert(path)
    # nvd_products_detail(path)
    # nvd_products_search(path)
    # nvd_vuln_detail(path)
    # nvd_vuln_search(path)
except KeyboardInterrupt:
    print("모든 작업을 중단합니다.")
    exit(0)