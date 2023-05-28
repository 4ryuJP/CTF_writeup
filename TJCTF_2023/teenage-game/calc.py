#!/usr/bin/env python3 
def solve_equation():
    solutions = []
    for x in range(-100, 255):  # xの範囲を適宜変更できます
        y = (-24 - x) / 90
        if y.is_integer():  # yが整数である場合のみ結果に追加する
            solutions.append((x, int(y)))
    return solutions

# 方程式の解を求める
result = solve_equation()

# 結果の出力
for solution in result:
    print(f"x = {solution[0]}, y = {solution[1]}")
