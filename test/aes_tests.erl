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
    F = fun({Const, Expect}, Last) ->
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

first_round_test() ->
    Expected = [<<16#58, 16#47, 16#08, 16#8B>>,
                <<16#15, 16#B6, 16#1C, 16#BA>>,
                <<16#59, 16#D4, 16#E2, 16#E8>>,
                <<16#CD, 16#39, 16#DF, 16#CE>>],
    Key0 = cryptopals_block:block_matrix(4, ?SIMPLE_KEY),
    State0 = [cryptopals_block:block_matrix(4, ?SIMPLE_PLAINTEXT)],
    {Key1, State1} = cryptopals_block:apply_aes(0, Key0, State0),
    {_Key2, State2} = cryptopals_block:apply_aes(1, Key1, State1),
    ?assertEqual([Expected], State2).

all_rounds_test() ->
    Expected = [<<"001f0e543c4e08596e221b0b4774311a">>,
                <<"5847088b15b61cba59d4e2e8cd39dfce">>,
                <<"43c6a9620e57c0c80908ebfe3df87f37">>,
                <<"7876305470767d23993c375b4b3934f1">>,
                <<"b1ca51ed08fc54e104b1c9d3e7b26c20">>,
                <<"9b512068235f22f05d1cbd322f389156">>,
                <<"149325778fa42be8c06024405e0f9275">>,
                <<"53398e5d430693f84f0a3b95855257bd">>,
                <<"66253c7470ce5aa8afd30f0aa3731354">>,
                <<"09668b78a2d19a65f0fce6c47b3b3089">>,
                <<"29c3505f571420f6402299b31a02d73a">>
               ],
    F = fun({I, E}, {K0, S0}) ->
        {K1, S1} = cryptopals_block:apply_aes(I, K0, S0),
        [[A, B, C, D]] = S1,
        Bytes = <<A/binary, B/binary, C/binary, D/binary>>,
        ?assertEqual({hex, E}, cryptopals_bytes:hex_encode(Bytes)),
        {K1, S1}
    end,
    lists:foldl(F,
                {cryptopals_block:block_matrix(4, ?SIMPLE_KEY),
                 [cryptopals_block:block_matrix(4, ?SIMPLE_PLAINTEXT)]},
                lists:zip(lists:seq(0, length(Expected) - 1), Expected)).

end_to_end_test() ->
    Expected = <<16#29, 16#C3, 16#50, 16#5F, 16#57, 16#14, 16#20, 16#F6,
                 16#40, 16#22, 16#99, 16#B3, 16#1A, 16#02, 16#D7, 16#3A>>,
    Output = cryptopals_block:aes(aes_128_ecb, encrypt, ?SIMPLE_KEY,
                                  ?SIMPLE_PLAINTEXT),
    ?assertEqual(Expected, Output).

full_text_test() ->
    Key = <<"YELLOW SUBMARINE">>,
    {ok, Input} = file:read_file(code:priv_dir(cryptopals) ++
                                 "/s1c7-expected.txt"),
    {ok, Contents} = file:read_file(code:priv_dir(cryptopals) ++ "/s1c7.txt"),
    F = fun(B, Acc) -> <<Acc/binary, B/binary>> end,
    Body = lists:foldl(F, <<>>, binary:split(Contents, <<"\n">>, [global])),
    Expected = cryptopals_bytes:base64_decode(
                 cryptopals_bytes:new_base64(Body)),
    Output = cryptopals_block:aes(aes_128_ecb, encrypt, Key, Input),
    ?assertEqual(Expected, Output).

matrix_binary([A, B, C, D]) ->
    <<A/binary, B/binary, C/binary, D/binary>>.
