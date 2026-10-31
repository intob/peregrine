import os, sys, subprocess, glob
R = sys.argv[1]; OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
cases = []
for d in sorted(os.listdir(R)):
    p = os.path.join(R, d)
    if not os.path.exists(p + '/resp.der') or os.path.getsize(p + '/resp.der') < 100: continue
    pems = sorted(glob.glob(p + '/c*.pem'), key=lambda x: int(os.path.basename(x)[1:-4]))
    chain = b''.join(subprocess.run(['openssl', 'x509', '-in', x, '-outform', 'DER'], capture_output=True, check=True).stdout for x in pems)
    name = d.replace('www.', '').replace('.', '-')
    open(f'{OUT}/{name}.chain.der', 'wb').write(chain)
    open(f'{OUT}/{name}.ocsp.der', 'wb').write(open(p + '/resp.der', 'rb').read())
    t = int(open(p + '/time').read())
    cases.append((name, t))
for n, t in cases: print(f'        .{{ .name = "{n}", .time = {t} }},')
