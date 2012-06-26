%macro setfd 2
        %ifnum %2
          push byte %2
          pop %1
        %else
        %if %1 <> %2
          mov %1, %2
        %endif
        %endif
%endmacro