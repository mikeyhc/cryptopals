-module(cryptopals_bytes_tests).
-include_lib("eunit/include/eunit.hrl").

set1_challenge1_test() ->
    Bytes = cryptopals_bytes:hex_decode(cryptopals_bytes:new_hex(<<"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d">>)),
    Base64 = cryptopals_bytes:base64_encode(Bytes),
    ?assertEqual(<<"I'm killing your brain like a poisonous mushroom">>, Bytes),
    ?assertEqual(cryptopals_bytes:new_base64(<<"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t">>), Base64).

