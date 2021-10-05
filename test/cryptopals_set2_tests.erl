-module(cryptopals_set2_tests).
-include_lib("eunit/include/eunit.hrl").

set2_challenge1_test() ->
    Input = <<"YELLOW SUBMARINE">>,
    Output = <<"YELLOW SUBMARINE\x04\x04\x04\x04">>,
    ?assertEqual(Output, cryptopals_block:pkcs7_padding(Input, 20)).
