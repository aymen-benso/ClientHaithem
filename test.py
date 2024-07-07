import pandas as pd

df = pd.read_csv("flow.csv")

array = df.to_numpy().sample(frac=0.1)
array = array[:, 1:]
print(array)

