
# Convert '8.8 hex' to a 'float'
try:
    while True:
        n_hex = int(input('Hex: 0x'), base=16)

        i_part = n_hex >> 8
        if i_part >= 0x80:
            i_part -= 2**8
            
        d_part = n_hex & 0x00ff

        n_float = i_part + d_part/256

        print(f'Float: {n_float}\n')

except:
    print('\nOK - Done\n')
