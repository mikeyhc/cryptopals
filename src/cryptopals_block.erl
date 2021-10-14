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
    aes_ecb_encrypt(16, Key, PlainText).

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

aes_ecb_encrypt(KeySize, Key, _PlainText) when size(Key) =/= KeySize ->
    error({invalid_key, Key, KeySize});
aes_ecb_encrypt(KeySize, Key, PlainText) ->
    MatrixSize = KeySize div 4,
    MatrixSize = 4, % TODO make this handle other sizes
    KeyMatrix = block_matrix(MatrixSize, Key),
    TextMatricies = to_matricies(MatrixSize, pkcs7_padding(PlainText, KeySize)),
    FinalMatrix = run_aes(0, KeyMatrix, TextMatricies),
    from_matricies(FinalMatrix).

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

run_aes(11, _Key, State) -> State;
run_aes(N, Key0, State0) ->
    {Key1, State1} = apply_aes(N, Key0, State0),
    run_aes(N + 1, Key1, State1).

apply_aes(0, Key, State) ->
    {Key, lists:map(fun(S) -> matrix_add(Key, S) end, State)};
apply_aes(10, Key0, State0) ->
    Key1 = aes_roundkey(roundkey_const(10), Key0),
    State1 = lists:map(fun(S) -> state_transform(S, true) end, State0),
    {Key1, lists:map(fun(S) -> matrix_add(S, Key1) end, State1)};
apply_aes(N, Key0, State0) ->
    Key1 = aes_roundkey(roundkey_const(N), Key0),
    State1 = lists:map(fun state_transform/1, State0),
    {Key1, lists:map(fun(S) -> matrix_add(S, Key1) end, State1)}.

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

state_transform(StateMatrix) ->
    state_transform(StateMatrix, false).

state_transform(StateMatrix0, SkipMix) ->
    StateMatrix1 = lists:map(fun byte_substitution/1, StateMatrix0),
    TSM1 = transpose(StateMatrix1),
    TSM2 = lists:map(fun({Idx, L}) -> circular_left_shift(Idx, L) end,
                     lists:zip(lists:seq(0, 3), TSM1)),
    StateMatrix2 = transpose(TSM2),
    if SkipMix -> StateMatrix2;
       true -> mix_column(StateMatrix2)
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


mix_column(Input) ->
    lists:map(fun mix_single_column/1, Input).

mix_single_column(A) ->
    LA = binary_to_list(A),
    F = fun(X) -> ((X bsl 1) band 16#ff) bxor (((X bsr 7) band 1) * 16#1B) end,
    LB = lists:map(F, LA),
    Nth = fun lists:nth/2,
    R = [Nth(1, LB) bxor Nth(4, LA) bxor Nth(3, LA) bxor Nth(2, LB) bxor
         Nth(2, LA),
         Nth(2, LB) bxor Nth(1, LA) bxor Nth(4, LA) bxor Nth(3, LB) bxor
         Nth(3, LA),
         Nth(3, LB) bxor Nth(2, LA) bxor Nth(1, LA) bxor Nth(4, LB) bxor
         Nth(4, LA),
         Nth(4, LB) bxor Nth(3, LA) bxor Nth(2, LA) bxor Nth(1, LB) bxor
         Nth(1, LA)
        ],
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

add_round_constant(Const, <<A, B, C, D>>) ->
    CA = Const bxor A,
    <<CA, B, C, D>>.
