from cve.meta_data import products_total
from cve.cve_details import smu_cve_details
from kb_cert.kb_cert import kb_cert
from nvd.products.nvd_products_detail import nvd_products_detail
from nvd.products.nvd_products_search import nvd_products_search
from nvd.vuln.nvd_vuln_detail import nvd_vuln_detail
from nvd.vuln.nvd_vuln_search import nvd_vuln_search

# 저장 파일 및 위치
path = '../data/final/'
err = open("error.txt", "wt")
smu_cve_details(err, path, 1, products_total[0:6])
smu_cve_details(err, path, 2, products_total[6:12])
smu_cve_details(err, path, 3, products_total[12:])
err.close()

kb_cert(path)
nvd_products_detail(path)
nvd_products_search(path)
nvd_vuln_detail(path)
nvd_vuln_search(path)