import os
import pandas as pd


path = "/home/jkjan/Desktop/GitHubRepos/Crawling/data/CVE/"
files = sorted(os.listdir(path))

key = 1
for f in files:
    df = pd.read_csv(path + f, encoding="utf8")
    df['ID'] = 0
    columns = ["ID"] + [df.columns[i] for i in range(len(df.columns)-1)]
    df = df[columns]

    for d in range(len(df)):
        df['ID'][d] = key
        key += 1
    df.to_csv(path + "keyed/" + f, encoding="utf8", index=False)