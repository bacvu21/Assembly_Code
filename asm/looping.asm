ORIGINAL 0x8000 ; start of original 

Count: 

    cmp #10, r0 
    je endprog 
    inc r0    ;add 1 into r1
    jmp Count ;# is the data and not have # is the address 

endprog:
    end