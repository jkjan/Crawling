from smu_cvedetails import smu_cvedetails
from smu_kb_cert import kb_cert
from smu_nvd_products_detail import nvd_products_detail
from smu_nvd_products_search import nvd_products_search
from smu_nvd_vuln_detail import nvd_vuln_detail
from smu_nvd_vuln_search import nvd_vuln_search

# 저장 파일 및 위치
path = '../data/final/'
err = open("error.txt", "wt")

from smu_cvedetails_1 import products, vendorIds, productIds, years, trcs, shas
smu_cvedetails(err, path, 1, products, vendorIds, productIds, years, trcs, shas)

from smu_cvedetails_2 import products, vendorIds, productIds, years, trcs, shas
smu_cvedetails(err, path, 2, products, vendorIds, productIds, years, trcs, shas)

from smu_cvedetails_3 import products, vendorIds, productIds, years, trcs, shas
smu_cvedetails(err, path, 3, products, vendorIds, productIds, years, trcs, shas)

err.close()

kb_cert(path)
nvd_products_detail(path)
nvd_products_search(path)
nvd_vuln_detail(path)
nvd_vuln_search(path)