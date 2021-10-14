-module(aes_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SIMPLE_KEY, <<"Thats my Kung Fu">>).
-define(SIMPLE_PLAINTEXT, <<"Two One Nine Two">>).

block_matrix_test() ->
    Expected = [<<16#54, 16#68, 16#61, 16#74>>,
                <<16#73, 16#20, 16#6D, 16#79>>,
                <<16#20, 16#4B, 16#75, 16#6E>>,
                <<16#67, 16#20, 16#46, 16#75>>],
    ?assertEqual(Expected, cryptopals_block:block_matrix(4, ?SIMPLE_KEY)).

first_roundkey_test() ->
    Expected = cryptopals_bytes:new_hex(<<"e232fcf191129188b159e4e6d679a293">>),
    Matrix = cryptopals_block:block_matrix(4, ?SIMPLE_KEY),
    Output = cryptopals_block:aes_roundkey(16#01, Matrix),
    MatrixBinary = matrix_binary(Output),
    ?assertEqual(Expected, cryptopals_bytes:hex_encode(MatrixBinary)).

all_roundkey_test() ->
    Expected = [<<"e232fcf191129188b159e4e6d679a293">>,
                <<"56082007c71ab18f76435569a03af7fa">>,
                <<"d2600de7157abc686339e901c3031efb">>,
                <<"a11202c9b468bea1d75157a01452495b">>,
                <<"b1293b3305418592d210d232c6429b69">>,
                <<"bd3dc287b87c47156a6c9527ac2e0e4e">>,
                <<"cc96ed1674eaaa031e863f24b2a8316a">>,
                <<"8e51ef21fabb4522e43d7a0656954b6c">>,
                <<"bfe2bf904559fab2a16480b4f7f1cbd8">>,
                <<"28fddef86da4244accc0a4fe3b316f26">>],
    Constants = [16#01, 16#02, 16#04, 16#08, 16#10,
                 16#20, 16#40, 16#80, 16#1B, 16#36],
    F = fun(In={Const, Expect}, Last) ->
                io:format("~p~n", [In]),
                LastBytes = cryptopals_bytes:hex_decode(Last),
                Matrix = cryptopals_block:block_matrix(4, LastBytes),
                [A, B, C, D] = cryptopals_block:aes_roundkey(Const, Matrix),
                CurrentBytes = <<A/binary, B/binary, C/binary, D/binary>>,
                CurrentHex = cryptopals_bytes:hex_encode(CurrentBytes),
                ?assertEqual(cryptopals_bytes:new_hex(Expect), CurrentHex),
                CurrentHex
        end,
    lists:foldl(F, cryptopals_bytes:hex_encode(?SIMPLE_KEY),
                lists:zip(Constants, Expected)).

apply_aes_test() ->
    KeyMatrix0 = cryptopals_block:block_matrix(4, ?SIMPLE_KEY),
    TextMatrix = cryptopals_block:block_matrix(4, ?SIMPLE_PLAINTEXT),
    Expected0 = [<<16#00, 16#1F, 16#0E, 16#54>>,
                 <<16#3C, 16#4E, 16#08, 16#59>>,
                 <<16#6E, 16#22, 16#1B, 16#0B>>,
                 <<16#47, 16#74, 16#31, 16#1A>>],
    Round0 = cryptopals_block:apply_aes(KeyMatrix0, TextMatrix),
    ?assertEqual(Expected0, Round0).

apply_state_transform_test() ->
    Expected = [<<16#BA, 16#75, 16#F4, 16#7A>>,
                <<16#84, 16#A4, 16#8D, 16#32>>,
                <<16#E8, 16#8D, 16#06, 16#0E>>,
                <<16#1B, 16#40, 16#7D, 16#5D>>],
    Input = [<<16#00, 16#1F, 16#0E, 16#54>>,
             <<16#3C, 16#4E, 16#08, 16#59>>,
             <<16#6E, 16#22, 16#1B, 16#0B>>,
             <<16#47, 16#74, 16#31, 16#1A>>],
    Output = cryptopals_block:state_transform(Input),
    ?assertEqual(Expected, Output).

matrix_binary([A, B, C, D]) ->
    <<A/binary, B/binary, C/binary, D/binary>>.
