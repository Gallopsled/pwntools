%macro setfd 2
        %ifnum %2
          %if %2 == 0
            xor %1, %1
          %else
            push byte %2
            pop %1
          %endif
        %else
        %if %1 <> %2
          mov %1, %2
        %endif
        %endif
%endmacro