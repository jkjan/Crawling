import pandas as pd

def save(res, cols, standard, saveFile):
    # 최종데이터를 dataframe으로 변경하고 위에서 선언한 standard 기준으로 정렬하고 index 재설정
    df = pd.DataFrame(res, columns=cols).sort_values(by=standard).reset_index(drop=True)
    # 위 dataframe 변환 작업 후 출력
    print(df)

    # 변환한 dataframe을 코드 상단에서 선언한 saveFile 경로로 저장
    df.to_csv(saveFile, mode='w', encoding="utf8", index=False)

    # 저장된 csv가 엑셀로 실행하면 한글이 깨짐현상이 발생됩니다.
    # 메모장으로 실행시킨뒤 다른 이름으로 저장으로 해서 인코딩을 'ANSI'로 해주시고 저장 후 엑셀로 실행하면 한글이 잘 나옵니다!

    # end
    print('finish')