
# Convert a 'float' to '8.8 hex'

import math

try:
    while True:
        n_float = float(input('Float: '))

        i_part = math.floor(n_float)
        d_part = n_float - i_part
        
        if i_part < 0:
            i_part += 2**8

        i_part = i_part << 8
        d_part = int(d_part * 256)
        
        n_hex = hex(i_part + d_part)
        
        print(f'Hex: {n_hex}\n')

except:
    print('\nOK - Done\n')
