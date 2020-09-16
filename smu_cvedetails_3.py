# 조사할 product 목록
products = [
    # 'Apple-Iphone-Os',
    # 'Google-Android',
    # 'Zephyrproject-Zephyr',
    # 'Apple-Watch-Os',
    # 'Microsoft-Windows-10',
    # 'Windriver-Vxworks',
    # 'Linux',
    # 'Linux-Audit',
    # 'Linux-Direct-Connect',
    # 'Linux-Ipsec-Tools-Racoon-Daemon',
    # 'Linux-Kernel1',
    # 'Linux-Kernel2',
    'Linux-Linux-Kernel',
    'Linux-Linux-Kernel-I40e-i40evf',
    'Linux-Linux-Kernel-Ixgbe',
    'Linux-Linux-Kernel-rt',
    'Linux-Systemd',
    'Linux-Util-linux'
]

# 조사할 vendor id 목록
vendorIds = {
    # 'Google-Android': 1224,
    # 'Apple-Iphone-Os': 49,
    # 'Zephyrproject-Zephyr': 19255,
    # 'Apple-Watch-Os': 49,
    # 'Microsoft-Windows-10': 26,
    # 'Windriver-Vxworks': 95,
    # 'Linux': 33,
    # 'Linux-Audit': 33,
    # 'Linux-Direct-Connect': 33,
    # 'Linux-Ipsec-Tools-Racoon-Daemon': 33,
    # 'Linux-Kernel1': 33,
    # 'Linux-Kernel2': 33,
    'Linux-Linux-Kernel': 33,
    'Linux-Linux-Kernel-I40e-i40evf': 33,
    'Linux-Linux-Kernel-Ixgbe': 33,
    'Linux-Linux-Kernel-rt': 33,
    'Linux-Systemd': 33,
    'Linux-Util-linux': 33
}

# 조사할 product id 목록
productIds = {
    # 'Google-Android': 19997,
    # 'Apple-Iphone-Os': 15556,
    # 'Zephyrproject-Zephyr': 50119,
    # 'Apple-Watch-Os': 32530,
    # 'Microsoft-Windows-10': 32238,
    # 'Windriver-Vxworks': 15063,
    # 'Linux': 0,
    # 'Linux-Audit': 13730,
    # 'Linux-Direct-Connect': 14392,
    # 'Linux-Ipsec-Tools-Racoon-Daemon': 14771,
    # 'Linux-Kernel1': 6861,
    # 'Linux-Kernel2': 17489,
    'Linux-Linux-Kernel': 47,
    'Linux-Linux-Kernel-I40e-i40evf': 43288,
    'Linux-Linux-Kernel-Ixgbe': 43287,
    'Linux-Linux-Kernel-rt': 34136,
    'Linux-Systemd': 22614,
    'Linux-Util-linux': 13878
}

# 검색할 year
years = {
    # 'Google-Android': 2019,
    # 'Apple-Iphone-Os': 2019,
    # 'Zephyrproject-Zephyr': 0,
    # 'Apple-Watch-Os': 0,
    # 'Microsoft-Windows-10': 0,
    # 'Windriver-Vxworks': 0,
    # 'Linux': 0,
    # 'Linux-Audit': 0,
    # 'Linux-Direct-Connect': 0,
    # 'Linux-Ipsec-Tools-Racoon-Daemon': 0,
    # 'Linux-Kernel1': 0,
    # 'Linux-Kernel2': 0,
    'Linux-Linux-Kernel': 0,
    'Linux-Linux-Kernel-I40e-i40evf': 0,
    'Linux-Linux-Kernel-Ixgbe': 0,
    'Linux-Linux-Kernel-rt': 0,
    'Linux-Systemd': 0,
    'Linux-Util-linux': 0
}

# 검색할 trcs
trcs = {
    # 'Google-Android': 103,
    # 'Apple-Iphone-Os': 156,
    # 'Zephyrproject-Zephyr': 4,
    # 'Apple-Watch-Os': 2,
    # 'Microsoft-Windows-10': 1080,
    # 'Windriver-Vxworks': 25,
    # 'Linux': 2368,
    # 'Linux-Audit': 1,
    # 'Linux-Direct-Connect': 2,
    # 'Linux-Ipsec-Tools-Racoon-Daemon': 1,
    # 'Linux-Kernel1': 1,
    # 'Linux-Kernel2': 14,
    'Linux-Linux-Kernel': 2355,
    'Linux-Linux-Kernel-I40e-i40evf': 1,
    'Linux-Linux-Kernel-Ixgbe': 1,
    'Linux-Linux-Kernel-rt': 2,
    'Linux-Systemd': 1,
    'Linux-Util-linux': 4
}

# 조사할 product hash key
shas = {
    # 'Google-Android': '&sha=65688f66fb2607f9ebc84c1102561ceeaf53d8e3',
    # 'Apple-Iphone-Os': '&sha=9268e05c272522ad7ffb4839270cfc837249a395',
    # 'Zephyrproject-Zephyr': '&sha=87ba9c30c0a32b596cdb67110cc51b643c7458d6',
    # 'Apple-Watch-Os': '&sha=b40b19fa2def1a46a655790fbba12f99e96c921f',
    # 'Microsoft-Windows-10': '&sha=41e451b72c2e412c0a1cb8cb1dcfee3d16d51c44',
    # 'Windriver-Vxworks': '&sha=362cecfc66d6e06c3491afe8f86ee9a435ddd697',
    # 'Linux': '&sha=2f79d8daa05f3cbce8cd668c2f5513fece73c35b',
    # 'Linux-Audit': '&sha=a4fdcd43b7d8e1e4ca89419cd110dbb3eb264f37',
    # 'Linux-Direct-Connect': '&sha=51b26927c5609010a8d5dd59b2d5f04f13609284',
    # 'Linux-Ipsec-Tools-Racoon-Daemon': '&sha=6257621264310525b91bda41c8a517d3b6bf5973',
    # 'Linux-Kernel1': '&sha=b775008fb26b4cc121d16dc1c4637deb2d9e6ea9',
    # 'Linux-Kernel2': '&sha=8c5cb41806770918dce520ff5abdfb5c349c0964',
    'Linux-Linux-Kernel': '&sha=544260ec3a86a7e17f8b02b39d6342815d8d4bd5',
    'Linux-Linux-Kernel-I40e-i40evf': '&sha=e747b8ae84cb5bfc2eaca621ad69c1d426bd79ee',
    'Linux-Linux-Kernel-Ixgbe': '&sha=c707f305c9dc4106710d8057e7f99c63dad56d83',
    'Linux-Linux-Kernel-rt': '&sha=0f1ae2f0090e43ebb9338c833b424db5996e74ac',
    'Linux-Systemd': '&sha=89ad2da99dcc01842da0b6892b3bfd0bb6ae3d0a',
    'Linux-Util-linux': '&sha=2c6de89433948b23942a8760161a66b205684e2a'
}
