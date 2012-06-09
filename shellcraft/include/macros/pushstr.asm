bits 32
%macro pushstr 1
        %strlen i %1
        %rep i / 4
        %substr xxxx %1 i-3,i
        push xxxx
        %assign i i - 4
        %endrep
        %if i == 1
          %substr x %1 1
          %strcat xx 'X', x
          push word xx
          inc esp
        %else
        %if i == 2
          %substr xx %1 1, 2
          push word xx
        %else
        %if i == 3
          %substr xxx %1 1, 3
          %strcat xxxx 'X', xxx
          push xxxx
          inc esp
        %endif
        %endif
        %endif
%endmacro
