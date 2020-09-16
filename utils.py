import pandas as pd

def save(res, cols, standard, save_file):
    # 최종데이터를 dataframe 으로 변경하고 위에서 선언한 standard 기준으로 정렬하고 index 재설정
    df = pd.DataFrame(res, columns=cols).sort_values(by=standard).reset_index(drop=True)

    # 위 dataframe 변환 작업 후 출력
    print(df)

    # 변환한 dataframe 을 코드 상단에서 선언한 save_file 경로로 저장
    df.to_csv(save_file, mode='w', encoding="utf8", index=False)

    print('finished')