;edi has the pointer to mem
;esi has the size
;rsp top points to eip
sub rsp, rsi ;allocate space on the stack. Instead, we could have starteds from the stack top and go down byte by byte but that would break LOAD!
xor rcx, rcx
xor al, al
Copy_input:
cmp rsi, rcx
je  Slice_code
inc rdi
inc rsp
mov al, byte ptr [rdi-1]
mov byte ptr [rsp-1], al
inc rcx
jmp Copy_input
Slice_code: ;the slice can assume the esp to esp + size have the input

