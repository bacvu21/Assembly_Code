ORIGIN 0x8000 

    data #3, R0 
    data #2, R1
    add R0, R1  ; R1 =  5
    sub R1 , R0 ; R0 = 3  -- des is R0 
    mult R0, R0  ; R0 = 3*3 = 9 
    div R0, R1  ; 9/5  q=  1 , remainder = 4 --> r 0 = 1, r1 = 4 

    end