#use with PyInjector
print("######")
for item in globals():
    print(item)

snak = globals()['Snake']
print(dir(snak))

print("Score:")
print(globals()['score'])
print(dir(globals()['Config']))

print(globals()['Config'].score)
print(globals()['Config'].speed)
print(globals()['check_snake_length'](globals()['Snake'], 7))
globals()['game_win']()