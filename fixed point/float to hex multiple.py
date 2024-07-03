import math

def float_to_8_8_hex(n_float):
    i_part = math.floor(n_float)
    d_part = n_float - i_part

    if i_part < 0:
        i_part += 2**8

    i_part = i_part << 8
    d_part = int(d_part * 256)

    n_hex = hex(i_part + d_part)

    return n_hex

try:
    values = [float(x) for x in input('Enter a list of floats separated by spaces: ').split()]
    
    hex_results = [float_to_8_8_hex(val) for val in values]

    for val, hex_result in zip(values, hex_results):
        print(f'Float: {val}  |  Hex: {hex_result}')

except ValueError:
    print('Invalid input. Please enter valid float values.')

except Exception as e:
    print(f'Error: {e}')

print('\nOK - Done\n')
