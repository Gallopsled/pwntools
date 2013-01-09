        ;; sort(int *array, int elems)
sort:
        %define arg_array (esp + 0x4)
        %define arg_elems (esp + 0x8)
        mov eax, [arg_array]
        mov ecx, [arg_elems]
        dec ecx
        shl ecx, 2              ; elems * 4
        add ecx, eax
        push ecx
        push eax
        call sort_aux
        add esp, 8
        ret

        ;; sort_aux(int *beg, int *end)
sort_aux:
        push esi
        push edi
        %define arg_beg (esp + 0xc)
        %define arg_end (esp + 0x10)
        %macro swap 2
          mov eax, [%1]
          mov edx, [%2]
          mov [%1], edx
          mov [%2], eax
        %endmacro

        mov esi, [arg_beg]
        mov edi, [arg_end]      ; right = end
        cmp esi, edi
        jae .ret                ; left >= right

        mov ecx, edi
        sub ecx, esi
        shr ecx, 3
        shl ecx, 2              ; round
        add ecx, esi            ; (end - beg) / 2
        swap ecx, esi           ; swap to beginning
        mov ecx, [esi]          ; pivot
        add esi, 4              ; left = beg + 1
.loop:
        cmp esi, edi
        ja .loop_exit           ; left > right
        cmp [esi], ecx
        jbe .no_swap            ; array[left] <= pivot
        swap esi, edi
        sub edi, 4              ; right--
        jmp .loop
.no_swap:
        add esi, 4              ; left++
        jmp .loop
.loop_exit:
        ;; swap pivot elm in between partitions
        sub esi, 4
        mov ecx, [arg_beg]
        swap ecx, esi
        ;; recursively sort first part
        sub esi, 4
        push esi                ; end of first partition
        push ecx                ; beg
        call sort_aux
        add esp, 0x8
        ;; Recursively sort second part
        mov eax, [arg_end]
        add esi, 8
        push eax                ; end
        push esi                ; beginning of second partition
        call sort_aux
        add esp, 8
.ret:
        pop edi
        pop esi
        ret
