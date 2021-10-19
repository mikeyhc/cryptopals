-module(cryptopals_block).

-export([pkcs7_padding/2, aes/4]).
-export_type([aes_mode/0]).

-ifdef(TEST).
-compile(export_all).
-endif.

-type aes_mode() :: aes_128_ecb.
-type aes_operation() :: encrypt | decrypt.

%% public api

-spec pkcs7_padding(binary(), pos_integer()) -> binary().
pkcs7_padding(Message, BlockSize) ->
    PadSize = size(Message) rem BlockSize,
    if PadSize =:= 0 -> Message;
       true ->
           PadLen = BlockSize - PadSize,
           Pad = list_to_binary(lists:duplicate(PadLen, PadLen)),
           <<Message/binary, Pad/binary>>
    end.

-spec aes(aes_mode(), aes_operation(), binary(), binary()) -> binary().
aes(aes_128_ecb, encrypt, Key, PlainText) ->
    aes_ecb_encrypt(16, Key, PlainText);
aes(aes_128_ecb, decrypt, Key, CipherText) ->
    aes_ecb_decrypt(16, Key, CipherText).

%% internal functions

forward_sbox(Byte) ->
    SBox = {{16#63, 16#7c, 16#77, 16#7b, 16#f2, 16#6b, 16#6f, 16#c5,
             16#30, 16#01, 16#67, 16#2b, 16#fe, 16#d7, 16#ab, 16#76},
            {16#ca, 16#82, 16#c9, 16#7d, 16#fa, 16#59, 16#47, 16#f0,
             16#ad, 16#d4, 16#a2, 16#af, 16#9c, 16#a4, 16#72, 16#c0},
            {16#b7, 16#fd, 16#93, 16#26, 16#36, 16#3f, 16#f7, 16#cc,
             16#34, 16#a5, 16#e5, 16#f1, 16#71, 16#d8, 16#31, 16#15},
            {16#04, 16#c7, 16#23, 16#c3, 16#18, 16#96, 16#05, 16#9a,
             16#07, 16#12, 16#80, 16#e2, 16#eb, 16#27, 16#b2, 16#75},
            {16#09, 16#83, 16#2c, 16#1a, 16#1b, 16#6e, 16#5a, 16#a0,
             16#52, 16#3b, 16#d6, 16#b3, 16#29, 16#e3, 16#2f, 16#84},
            {16#53, 16#d1, 16#00, 16#ed, 16#20, 16#fc, 16#b1, 16#5b,
             16#6a, 16#cb, 16#be, 16#39, 16#4a, 16#4c, 16#58, 16#cf},
            {16#d0, 16#ef, 16#aa, 16#fb, 16#43, 16#4d, 16#33, 16#85,
             16#45, 16#f9, 16#02, 16#7f, 16#50, 16#3c, 16#9f, 16#a8},
            {16#51, 16#a3, 16#40, 16#8f, 16#92, 16#9d, 16#38, 16#f5,
             16#bc, 16#b6, 16#da, 16#21, 16#10, 16#ff, 16#f3, 16#d2},
            {16#cd, 16#0c, 16#13, 16#ec, 16#5f, 16#97, 16#44, 16#17,
             16#c4, 16#a7, 16#7e, 16#3d, 16#64, 16#5d, 16#19, 16#73},
            {16#60, 16#81, 16#4f, 16#dc, 16#22, 16#2a, 16#90, 16#88,
             16#46, 16#ee, 16#b8, 16#14, 16#de, 16#5e, 16#0b, 16#db},
            {16#e0, 16#32, 16#3a, 16#0a, 16#49, 16#06, 16#24, 16#5c,
             16#c2, 16#d3, 16#ac, 16#62, 16#91, 16#95, 16#e4, 16#79},
            {16#e7, 16#c8, 16#37, 16#6d, 16#8d, 16#d5, 16#4e, 16#a9,
             16#6c, 16#56, 16#f4, 16#ea, 16#65, 16#7a, 16#ae, 16#08},
            {16#ba, 16#78, 16#25, 16#2e, 16#1c, 16#a6, 16#b4, 16#c6,
             16#e8, 16#dd, 16#74, 16#1f, 16#4b, 16#bd, 16#8b, 16#8a},
            {16#70, 16#3e, 16#b5, 16#66, 16#48, 16#03, 16#f6, 16#0e,
             16#61, 16#35, 16#57, 16#b9, 16#86, 16#c1, 16#1d, 16#9e},
            {16#e1, 16#f8, 16#98, 16#11, 16#69, 16#d9, 16#8e, 16#94,
             16#9b, 16#1e, 16#87, 16#e9, 16#ce, 16#55, 16#28, 16#df},
            {16#8c, 16#a1, 16#89, 16#0d, 16#bf, 16#e6, 16#42, 16#68,
             16#41, 16#99, 16#2d, 16#0f, 16#b0, 16#54, 16#bb, 16#16}},
    A = Byte bsr 4 + 1,
    B = Byte band 16#f + 1,
    element(B, element(A, SBox)).

reverse_sbox(Byte) ->
    SBox = {{16#52, 16#09, 16#6A, 16#D5, 16#30, 16#36, 16#A5, 16#38,
             16#BF, 16#40, 16#A3, 16#9E, 16#81, 16#F3, 16#D7, 16#FB},
            {16#7C, 16#E3, 16#39, 16#82, 16#9B, 16#2F, 16#FF, 16#87,
             16#34, 16#8E, 16#43, 16#44, 16#C4, 16#DE, 16#E9, 16#CB},
            {16#54, 16#7B, 16#94, 16#32, 16#A6, 16#C2, 16#23, 16#3D,
             16#EE, 16#4C, 16#95, 16#0B, 16#42, 16#FA, 16#C3, 16#4E},
            {16#08, 16#2E, 16#A1, 16#66, 16#28, 16#D9, 16#24, 16#B2,
             16#76, 16#5B, 16#A2, 16#49, 16#6D, 16#8B, 16#D1, 16#25},
            {16#72, 16#F8, 16#F6, 16#64, 16#86, 16#68, 16#98, 16#16,
             16#D4, 16#A4, 16#5C, 16#CC, 16#5D, 16#65, 16#B6, 16#92},
            {16#6C, 16#70, 16#48, 16#50, 16#FD, 16#ED, 16#B9, 16#DA,
             16#5E, 16#15, 16#46, 16#57, 16#A7, 16#8D, 16#9D, 16#84},
            {16#90, 16#D8, 16#AB, 16#00, 16#8C, 16#BC, 16#D3, 16#0A,
             16#F7, 16#E4, 16#58, 16#05, 16#B8, 16#B3, 16#45, 16#06},
            {16#D0, 16#2C, 16#1E, 16#8F, 16#CA, 16#3F, 16#0F, 16#02,
             16#C1, 16#AF, 16#BD, 16#03, 16#01, 16#13, 16#8A, 16#6B},
            {16#3A, 16#91, 16#11, 16#41, 16#4F, 16#67, 16#DC, 16#EA,
             16#97, 16#F2, 16#CF, 16#CE, 16#F0, 16#B4, 16#E6, 16#73},
            {16#96, 16#AC, 16#74, 16#22, 16#E7, 16#AD, 16#35, 16#85,
             16#E2, 16#F9, 16#37, 16#E8, 16#1C, 16#75, 16#DF, 16#6E},
            {16#47, 16#F1, 16#1A, 16#71, 16#1D, 16#29, 16#C5, 16#89,
             16#6F, 16#B7, 16#62, 16#0E, 16#AA, 16#18, 16#BE, 16#1B},
            {16#FC, 16#56, 16#3E, 16#4B, 16#C6, 16#D2, 16#79, 16#20,
             16#9A, 16#DB, 16#C0, 16#FE, 16#78, 16#CD, 16#5A, 16#F4},
            {16#1F, 16#DD, 16#A8, 16#33, 16#88, 16#07, 16#C7, 16#31,
             16#B1, 16#12, 16#10, 16#59, 16#27, 16#80, 16#EC, 16#5F},
            {16#60, 16#51, 16#7F, 16#A9, 16#19, 16#B5, 16#4A, 16#0D,
             16#2D, 16#E5, 16#7A, 16#9F, 16#93, 16#C9, 16#9C, 16#EF},
            {16#A0, 16#E0, 16#3B, 16#4D, 16#AE, 16#2A, 16#F5, 16#B0,
             16#C8, 16#EB, 16#BB, 16#3C, 16#83, 16#53, 16#99, 16#61},
            {16#17, 16#2B, 16#04, 16#7E, 16#BA, 16#77, 16#D6, 16#26,
             16#E1, 16#69, 16#14, 16#63, 16#55, 16#21, 16#0C, 16#7D}},
    A = Byte bsr 4 + 1,
    B = Byte band 16#f + 1,
    element(B, element(A, SBox)).


aes_ecb_encrypt(KeySize, Key, _PlainText) when size(Key) =/= KeySize ->
    error({invalid_key, Key, KeySize});
aes_ecb_encrypt(KeySize, Key, PlainText) ->
    MatrixSize = KeySize div 4,
    MatrixSize = 4, % TODO make this handle other sizes
    KeyMatrix = block_matrix(MatrixSize, Key),
    TextMatricies = to_matricies(MatrixSize, pkcs7_padding(PlainText, KeySize)),
    FinalMatrix = run_aes_encrypt(0, KeyMatrix, TextMatricies),
    from_matricies(FinalMatrix).

aes_ecb_decrypt(KeySize, Key, _CipherText) when size(Key) =/= KeySize ->
    error({invalid_key, Key, KeySize});
aes_ecb_decrypt(KeySize, Key, CipherText) ->
    MatrixSize = KeySize div 4,
    MatrixSize = 4, % TODO make this handle other sizes
    KeyMatrix = block_matrix(MatrixSize, Key),
    TextMatricies = to_matricies(MatrixSize, CipherText),
    FinalMatrix = run_aes_decrypt(0, KeyMatrix, TextMatricies),
    from_matricies(FinalMatrix). % TODO remove padding

to_matricies(Size, Input) when Size * Size =:= size(Input)->
    [block_matrix(Size, Input)];
to_matricies(Size, Input) ->
    MatrixSize = Size * Size,
    Head = binary:part(Input, 0, MatrixSize),
    Tail = binary:part(Input, MatrixSize, size(Input) - MatrixSize),
    [block_matrix(Size, Head)|to_matricies(Size, Tail)].

from_matricies(Matricies) ->
    Unmatrix = fun([A, B, C, D], Acc) ->
                       <<Acc/binary, A/binary, B/binary, C/binary, D/binary>>
               end,
    lists:foldl(Unmatrix, <<>>, Matricies).

run_aes_encrypt(11, _Key, State) -> State;
run_aes_encrypt(N, Key0, State0) ->
    {Key1, State1} = apply_aes_encrypt(N, Key0, State0),
    run_aes_encrypt(N + 1, Key1, State1).

apply_aes_encrypt(0, Key, State) ->
    {Key, lists:map(fun(S) -> matrix_add(Key, S) end, State)};
apply_aes_encrypt(10, Key0, State0) ->
    Key1 = aes_roundkey(roundkey_const(10), Key0),
    State1 = lists:map(fun(S) -> state_transform(S, Key1, true) end, State0),
    {Key1, State1};
apply_aes_encrypt(N, Key0, State0) ->
    Key1 = aes_roundkey(roundkey_const(N), Key0),
    State1 = lists:map(fun(M) -> state_transform(M, Key1) end, State0),
    {Key1, State1}.

run_aes_decrypt(11, _Key, State) -> State;
run_aes_decrypt(N, Key0, State0) ->
    {Key1, State1} = apply_aes_decrypt(N, Key0, State0),
    run_aes_decrypt(N + 1, Key1, State1).

apply_aes_decrypt(0, Key, State) ->
    {Key, lists:map(fun(S) -> matrix_add(Key, S) end, State)};
apply_aes_decrypt(10, Key0, State0) ->
    Key1 = aes_roundkey(roundkey_const(10), Key0),
    State1 = lists:map(fun(S) -> rstate_transform(S, Key1, true) end, State0),
    {Key1, State1};
apply_aes_decrypt(N, Key0, State0) ->
    Key1 = aes_roundkey(roundkey_const(N), Key0),
    State1 = lists:map(fun(M) -> rstate_transform(M, Key1) end, State0),
    {Key1, State1}.

roundkey_const(10) -> 16#36;
roundkey_const(9) -> 16#1B;
roundkey_const(N) when N > 0 andalso N < 9 ->
    1 bsl (N - 1).

matrix_add(A, B) ->
    Add = fun({X, Y}) -> X bxor Y end,
    F = fun({X, Y}) ->
        LX = binary_to_list(X),
        LY = binary_to_list(Y),
        list_to_binary(lists:map(Add, lists:zip(LX, LY)))
    end,
    lists:map(F, lists:zip(A, B)).

state_transform(StateMatrix, RoundKey) ->
    state_transform(StateMatrix, RoundKey, false).

state_transform(StateMatrix0, RoundKey, SkipMix) ->
    StateMatrix1 = lists:map(fun byte_substitution/1, StateMatrix0),
    TSM1 = transpose(StateMatrix1),
    TSM2 = lists:map(fun({Idx, L}) -> circular_left_shift(Idx, L) end,
                     lists:zip(lists:seq(0, 3), TSM1)),
    StateMatrix2 = transpose(TSM2),
    StateMatrix3 = if SkipMix -> StateMatrix2;
                      true -> mix_column(StateMatrix2)
                   end,
    matrix_add(StateMatrix3, RoundKey).

rstate_transform(StateMatrix, RoundKey) ->
    rstate_transform(StateMatrix, RoundKey, false).

rstate_transform(StateMatrix0, RoundKey, SkipMix) ->
    TSM0 = transpose(StateMatrix0),
    TSM1 = lists:map(fun({Idx, L}) -> circular_right_shift(Idx, L) end,
                     lists:zip(lists:seq(0, 3), TSM0)),
    StateMatrix1 = transpose(TSM1),
    StateMatrix2 = lists:map(fun rbyte_substitution/1, StateMatrix1),
    StateMatrix3 = matrix_add(StateMatrix2, RoundKey),
    if SkipMix -> StateMatrix3;
       true -> rmix_column(StateMatrix3)
    end.

transpose({[<<>>|_], L}) -> [L];
transpose({Ts, L}) ->
    [L|transpose(transpose_col(Ts, [], <<>>))];
transpose(L) ->
    transpose(transpose_col(L, [], <<>>)).

transpose_col([], Ts, Acc) -> {lists:reverse(Ts), Acc};
transpose_col([<<H, T/binary>>|R], Ts, Acc) ->
    transpose_col(R, [T|Ts], <<Acc/binary, H>>).

circular_left_shift(N, In) ->
    {A, B} = lists:split(N, binary_to_list(In)),
    list_to_binary(B ++ A).

circular_right_shift(N, In) ->
    {A, B} = lists:split(size(In) - N, binary_to_list(In)),
    list_to_binary(B ++ A).

mix_column(Input) ->
    lists:map(fun mix_single_column/1, Input).

rmix_column(Input) ->
    lists:map(fun rmix_single_column/1, Input).

etable(N) ->
    E = {{16#01, 16#03, 16#05, 16#0F, 16#11, 16#33, 16#55, 16#FF,
          16#1A, 16#2E, 16#72, 16#96, 16#A1, 16#F8, 16#13, 16#35},
         {16#5F, 16#E1, 16#38, 16#48, 16#D8, 16#73, 16#95, 16#A4,
          16#F7, 16#02, 16#06, 16#0A, 16#1E, 16#22, 16#66, 16#AA},
         {16#E5, 16#34, 16#5C, 16#E4, 16#37, 16#59, 16#EB, 16#26,
          16#6A, 16#BE, 16#D9, 16#70, 16#90, 16#AB, 16#E6, 16#31},
         {16#53, 16#F5, 16#04, 16#0C, 16#14, 16#3C, 16#44, 16#CC,
          16#4F, 16#D1, 16#68, 16#B8, 16#D3, 16#6E, 16#B2, 16#CD},
         {16#4C, 16#D4, 16#67, 16#A9, 16#E0, 16#3B, 16#4D, 16#D7,
          16#62, 16#A6, 16#F1, 16#08, 16#18, 16#28, 16#78, 16#88},
         {16#83, 16#9E, 16#B9, 16#D0, 16#6B, 16#BD, 16#DC, 16#7F,
          16#81, 16#98, 16#B3, 16#CE, 16#49, 16#DB, 16#76, 16#9A},
         {16#B5, 16#C4, 16#57, 16#F9, 16#10, 16#30, 16#50, 16#F0,
          16#0B, 16#1D, 16#27, 16#69, 16#BB, 16#D6, 16#61, 16#A3},
         {16#FE, 16#19, 16#2B, 16#7D, 16#87, 16#92, 16#AD, 16#EC,
          16#2F, 16#71, 16#93, 16#AE, 16#E9, 16#20, 16#60, 16#A0},
         {16#FB, 16#16, 16#3A, 16#4E, 16#D2, 16#6D, 16#B7, 16#C2,
          16#5D, 16#E7, 16#32, 16#56, 16#FA, 16#15, 16#3F, 16#41},
         {16#C3, 16#5E, 16#E2, 16#3D, 16#47, 16#C9, 16#40, 16#C0,
          16#5B, 16#ED, 16#2C, 16#74, 16#9C, 16#BF, 16#DA, 16#75},
         {16#9F, 16#BA, 16#D5, 16#64, 16#AC, 16#EF, 16#2A, 16#7E,
          16#82, 16#9D, 16#BC, 16#DF, 16#7A, 16#8E, 16#89, 16#80},
         {16#9B, 16#B6, 16#C1, 16#58, 16#E8, 16#23, 16#65, 16#AF,
          16#EA, 16#25, 16#6F, 16#B1, 16#C8, 16#43, 16#C5, 16#54},
         {16#FC, 16#1F, 16#21, 16#63, 16#A5, 16#F4, 16#07, 16#09,
          16#1B, 16#2D, 16#77, 16#99, 16#B0, 16#CB, 16#46, 16#CA},
         {16#45, 16#CF, 16#4A, 16#DE, 16#79, 16#8B, 16#86, 16#91,
          16#A8, 16#E3, 16#3E, 16#42, 16#C6, 16#51, 16#F3, 16#0E},
         {16#12, 16#36, 16#5A, 16#EE, 16#29, 16#7B, 16#8D, 16#8C,
          16#8F, 16#8A, 16#85, 16#94, 16#A7, 16#F2, 16#0D, 16#17},
         {16#39, 16#4B, 16#DD, 16#7C, 16#84, 16#97, 16#A2, 16#FD,
          16#1C, 16#24, 16#6C, 16#B4, 16#C7, 16#52, 16#F6, 16#01}},
    A = N bsr 4 + 1,
    B = N band 16#f + 1,
    element(B, element(A, E)).

ltable(N) ->
    L = {{false, 16#00, 16#19, 16#01, 16#32, 16#02, 16#1A, 16#C6,
          16#4B, 16#C7, 16#1B, 16#68, 16#33, 16#EE, 16#DF, 16#03},
         {16#64, 16#04, 16#E0, 16#0E, 16#34, 16#8D, 16#81, 16#EF,
          16#4C, 16#71, 16#08, 16#C8, 16#F8, 16#69, 16#1C, 16#C1},
         {16#7D, 16#C2, 16#1D, 16#B5, 16#F9, 16#B9, 16#27, 16#6A,
          16#4D, 16#E4, 16#A6, 16#72, 16#9A, 16#C9, 16#09, 16#78},
         {16#65, 16#2F, 16#8A, 16#05, 16#21, 16#0F, 16#E1, 16#24,
          16#12, 16#F0, 16#82, 16#45, 16#35, 16#93, 16#DA, 16#8E},
         {16#96, 16#8F, 16#DB, 16#BD, 16#36, 16#D0, 16#CE, 16#94,
          16#13, 16#5C, 16#D2, 16#F1, 16#40, 16#46, 16#83, 16#38},
         {16#66, 16#DD, 16#FD, 16#30, 16#BF, 16#06, 16#8B, 16#62,
          16#B3, 16#25, 16#E2, 16#98, 16#22, 16#88, 16#91, 16#10},
         {16#7E, 16#6E, 16#48, 16#C3, 16#A3, 16#B6, 16#1E, 16#42,
          16#3A, 16#6B, 16#28, 16#54, 16#FA, 16#85, 16#3D, 16#BA},
         {16#2B, 16#79, 16#0A, 16#15, 16#9B, 16#9F, 16#5E, 16#CA,
          16#4E, 16#D4, 16#AC, 16#E5, 16#F3, 16#73, 16#A7, 16#57},
         {16#AF, 16#58, 16#A8, 16#50, 16#F4, 16#EA, 16#D6, 16#74,
          16#4F, 16#AE, 16#E9, 16#D5, 16#E7, 16#E6, 16#AD, 16#E8},
         {16#2C, 16#D7, 16#75, 16#7A, 16#EB, 16#16, 16#0B, 16#F5,
          16#59, 16#CB, 16#5F, 16#B0, 16#9C, 16#A9, 16#51, 16#A0},
         {16#7F, 16#0C, 16#F6, 16#6F, 16#17, 16#C4, 16#49, 16#EC,
          16#D8, 16#43, 16#1F, 16#2D, 16#A4, 16#76, 16#7B, 16#B7},
         {16#CC, 16#BB, 16#3E, 16#5A, 16#FB, 16#60, 16#B1, 16#86,
          16#3B, 16#52, 16#A1, 16#6C, 16#AA, 16#55, 16#29, 16#9D},
         {16#97, 16#B2, 16#87, 16#90, 16#61, 16#BE, 16#DC, 16#FC,
          16#BC, 16#95, 16#CF, 16#CD, 16#37, 16#3F, 16#5B, 16#D1},
         {16#53, 16#39, 16#84, 16#3C, 16#41, 16#A2, 16#6D, 16#47,
          16#14, 16#2A, 16#9E, 16#5D, 16#56, 16#F2, 16#D3, 16#AB},
         {16#44, 16#11, 16#92, 16#D9, 16#23, 16#20, 16#2E, 16#89,
          16#B4, 16#7C, 16#B8, 16#26, 16#77, 16#99, 16#E3, 16#A5},
         {16#67, 16#4A, 16#ED, 16#DE, 16#C5, 16#31, 16#FE, 16#18,
          16#0D, 16#63, 16#8C, 16#80, 16#C0, 16#F7, 16#70, 16#07}},
    A = N bsr 4 + 1,
    B = N band 16#f + 1,
    element(B, element(A, L)).

gmul(0, _) -> 0;
gmul(_, 0) -> 0;
gmul(X, Y) ->
    etable((ltable(X) + ltable(Y)) rem 16#FF).

mix_single_column(<<A1, A2, A3, A4>>) ->
    R = [gmul(A1, 16#02) bxor gmul(A2, 16#03) bxor A3 bxor A4,
         A1 bxor gmul(A2, 16#02) bxor gmul(A3, 16#03) bxor A4,
         A1 bxor A2 bxor gmul(A3, 16#02) bxor gmul(A4, 16#03),
         gmul(A1, 16#03) bxor A2 bxor A3 bxor gmul(A4, 16#02)
        ],
    list_to_binary(R).

rmix_single_column(<<A1, A2, A3, A4>>) ->
    R = [gmul(A1, 16#0E) bxor gmul(A2, 16#0B) bxor gmul(A3, 16#0D)
         bxor gmul(A4, 16#09),
         gmul(A1, 16#09) bxor gmul(A2, 16#0E) bxor gmul(A3, 16#0B)
         bxor gmul(A4, 16#0D),
         gmul(A1, 16#0D) bxor gmul(A2, 16#09) bxor gmul(A3, 16#0E)
         bxor gmul(A4, 16#0B),
         gmul(A1, 16#0B) bxor gmul(A2, 16#0D) bxor gmul(A3, 16#09)
         bxor gmul(A4, 16#0E)],
    list_to_binary(R).

block_xor(A, B) ->
    F = fun({X, Y}) -> X bxor Y end,
    list_to_binary(lists:map(F, lists:zip(binary_to_list(A),
                                          binary_to_list(B)))).

block_matrix(Size, Text) ->
    R = block_matrix(Size, Text, []),
    Size = length(R),
    R.

block_matrix(Size, Text, Acc) when size(Text) =:= Size ->
    lists:reverse([Text|Acc]);
block_matrix(Size, Text, Acc) when size(Text) > Size ->
    Head = binary:part(Text, 0, Size),
    Tail = binary:part(Text, Size, size(Text) - Size),
    block_matrix(Size, Tail, [Head|Acc]).


aes_roundkey(Const, [W0, W1, W2, W3]) ->
    ShiftW3 = circular_byte_left_shift(W3),
    SubW3 = byte_substitution(ShiftW3),
    ConstW3 = add_round_constant(Const, SubW3),
    W4 = block_xor(W0, ConstW3),
    W5 = block_xor(W1, W4),
    W6 = block_xor(W2, W5),
    W7 = block_xor(W3, W6),
    [W4, W5, W6, W7].

circular_byte_left_shift(<<A, B, C, D>>) ->
    <<B, C, D, A>>.

byte_substitution(<<A, B, C, D>>) ->
    SA = forward_sbox(A),
    SB = forward_sbox(B),
    SC = forward_sbox(C),
    SD = forward_sbox(D),
    <<SA, SB, SC, SD>>.

rbyte_substitution(<<A, B, C, D>>) ->
    SA = reverse_sbox(A),
    SB = reverse_sbox(B),
    SC = reverse_sbox(C),
    SD = reverse_sbox(D),
    <<SA, SB, SC, SD>>.

add_round_constant(Const, <<A, B, C, D>>) ->
    CA = Const bxor A,
    <<CA, B, C, D>>.
