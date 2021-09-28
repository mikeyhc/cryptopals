-module(cryptopals_set1_tests).
-include_lib("eunit/include/eunit.hrl").

set1_challenge1_test() ->
    Bytes = cryptopals_bytes:hex_decode(cryptopals_bytes:new_hex(<<"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d">>)),
    Base64 = cryptopals_bytes:base64_encode(Bytes),
    ?assertEqual(<<"I'm killing your brain like a poisonous mushroom">>, Bytes),
    ?assertEqual(cryptopals_bytes:new_base64(<<"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t">>), Base64).

set1_challenge2_test() ->
    Input1 = cryptopals_bytes:hex_decode(cryptopals_bytes:new_hex(<<"1c0111001f010100061a024b53535009181c">>)),
    Input2 = cryptopals_bytes:hex_decode(cryptopals_bytes:new_hex(<<"686974207468652062756c6c277320657965">>)),
    Output = cryptopals_bytes:fixed_xor(Input1, Input2),
    ?assertEqual(<<"the kid don't play">>, Output),
    ?assertEqual(cryptopals_bytes:new_hex(<<"746865206b696420646f6e277420706c6179">>),
                 cryptopals_bytes:hex_encode(Output)).

set1_challenge3_test() ->
    Input = cryptopals_bytes:hex_decode(cryptopals_bytes:new_hex(<<"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736">>)),
    Output = cryptopals_cipher:single_xor(Input),
    ?assertEqual({88, <<"Cooking MC's like a pound of bacon">>}, Output).

set1_challenge4_test() ->
    {ok, Contents} = file:read_file(code:priv_dir(cryptopals) ++ "/s1c4.txt"),
    F = fun(B) ->
                Hex = cryptopals_bytes:new_hex(B),
                cryptopals_bytes:hex_decode(Hex)
        end,
    Lines = lists:map(F, binary:split(Contents, <<"\n">>, [global])),
    Output = cryptopals_cipher:find_xor_string(Lines),
    ?assertEqual({53,<<"Now that the party is jumping\n">>}, Output).

set1_challenge5_test() ->
    Input = <<"Burning 'em, if you ain't quick and nimble\n"
              "I go crazy when I hear a cymbal">>,
    Key = <<"ICE">>,
    Output = <<"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
               "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f">>,
    Hex = cryptopals_bytes:hex_encode(cryptopals_cipher:repeating_key_xor(Key, Input)),
    ?assertEqual(cryptopals_bytes:new_hex(Output), Hex).

hamming_distance_test() ->
    A = <<"this is a test">>,
    B = <<"wokka wokka!!!">>,
    ?assertEqual(37, cryptopals_bytes:hamming_distance(A, B)).

base64_decode_test() ->
    Decode = fun(B) ->
                     cryptopals_bytes:base64_decode(
                       cryptopals_bytes:new_base64(B))
             end,
    ?assertEqual(<<"Man">>, Decode(<<"TWFu">>)),
    ?assertEqual(<<"Ma">>, Decode(<<"TWE=">>)),
    ?assertEqual(<<"M">>, Decode(<<"TQ==">>)).

set1_challenge6_test() ->
    ExpectedKey = <<"Terminator X: Bring the noise">>,
    {ok, Text} = file:read_file(code:priv_dir(cryptopals) ++
                                "/s1c6-expected.txt"),
    {ok, Contents} = file:read_file(code:priv_dir(cryptopals) ++ "/s1c6.txt"),
    F = fun(B, Acc) -> <<Acc/binary, B/binary>> end,
    Body = lists:foldl(F, <<>>, binary:split(Contents, <<"\n">>, [global])),
    Input = cryptopals_bytes:base64_decode(cryptopals_bytes:new_base64(Body)),
    Key = cryptopals_cipher:find_xor_key(Input),
    ?assertEqual(29, size(Key)),
    ?assertEqual({ExpectedKey, Text},
                 {Key, cryptopals_cipher:repeating_key_xor(Key, Input)}).

set1_challenge7_test() ->
    Key = <<"YELLOW SUBMARINE">>,
    {ok, Text} = file:read_file(code:priv_dir(cryptopals) ++
                                "/s1c7-expected.txt"),
    {ok, Contents} = file:read_file(code:priv_dir(cryptopals) ++ "/s1c7.txt"),
    F = fun(B, Acc) -> <<Acc/binary, B/binary>> end,
    Body = lists:foldl(F, <<>>, binary:split(Contents, <<"\n">>, [global])),
    Input = cryptopals_bytes:base64_decode(cryptopals_bytes:new_base64(Body)),
    Output = crypto:crypto_one_time(aes_128_ecb, Key, Input,
                                    [{encrypt, false},
                                     {padding, pkcs_padding}]),
    ?assertEqual(Text, Output).
