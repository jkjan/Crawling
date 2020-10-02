import pandas as pd
import requests
from bs4 import BeautifulSoup
import time


def save(res, cols, standard, save_file):
    # 최종데이터를 dataframe 으로 변경하고 위에서 선언한 standard 기준으로 정렬하고 index 재설정
    df = pd.DataFrame(res, columns=cols).sort_values(by=standard).reset_index(drop=True)

    # 변환한 dataframe 을 코드 상단에서 선언한 save_file 경로로 저장
    df.to_csv(save_file, mode='w', encoding="utf8", index=False)


# url 에서 수프 가져오기
def get_soup(url):
    try:
        req = requests.get(url)
        return BeautifulSoup(req.text, 'html5lib')
    except requests.exceptions.ConnectionError as e:
        print("인터넷 연결을 확인하시길 바랍니다.")
        print(e)
        exit(0)


# 태그에서 정제된 텍스트 가져오기
def get_text(tag):
    return tag.text.strip().replace('\t', '')


# 데이터에 태그에서 얻어온 텍스트 추가
def append_to(data, tag):
    refined = get_text(tag)
    data.append(refined)
