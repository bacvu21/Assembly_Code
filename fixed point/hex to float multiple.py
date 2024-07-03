try:
    input_values = input('Enter a list of hex values separated by spaces: ').split()
    hex_values = [int(value, base=16) for value in input_values]

    float_values = []

    for n_hex in hex_values:
        i_part = n_hex >> 8
        if i_part >= 0x80:
            i_part -= 2**8

        d_part = n_hex & 0x00ff

        n_float = i_part + d_part/256
        float_values.append(n_float)

    print('List of Floats:')
    for float_value in float_values:
        print(float_value)

except ValueError as e:
    print(f'Error: {e}')

print('\nOK - Done\n')