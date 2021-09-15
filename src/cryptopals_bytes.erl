-module(cryptopals_bytes).

-export([new_hex/1, hex_decode/1]).
-export([new_base64/1, base64_encode/1]).
-export_type([hex/0, base64/0]).

-opaque hex() :: {hex, binary()}.
-opaque base64() :: {base64, binary()}.

-spec new_hex(binary()) -> hex().
new_hex(Bytes) -> {hex, Bytes}.

-spec new_base64(binary()) -> base64().
new_base64(Bytes) -> {base64, Bytes}.

-spec hex_decode(hex()) -> binary().
hex_decode({hex, HexStr}) ->
    hex_decode(HexStr, <<>>).

-spec base64_encode(binary()) -> base64().
base64_encode(Bytes) ->
    {base64, base64_encode(Bytes, <<>>)}.

% helper functions

hex_decode(<<>>, Acc) -> Acc;
hex_decode(<<HA, HB, Rest/binary>>, Acc) ->
    A = hexchar_decode(HA),
    B = hexchar_decode(HB),
    hex_decode(Rest, <<Acc/binary, (A bsl 4 + B)>>).

base64_encode(<<>>, Acc) -> Acc;
base64_encode(<<W:6, X:2>>, Acc) ->
    BW = base64char_encode(W),
    BX = base64char_encode(X bsl 4),
    io:format("~s~n", [Acc]),
    <<Acc/binary, BW, BX, "==">>;
base64_encode(<<W:6, X:6, Y:4>>, Acc) ->
    BW = base64char_encode(W),
    BX = base64char_encode(X),
    BY = base64char_encode(Y bsl 2),
    io:format("~s~n", [Acc]),
    <<Acc/binary, BW, BX, BY, "=">>;
base64_encode(<<W:6, X:6, Y:6, Z:6, Rest/binary>>, Acc) ->
    BW = base64char_encode(W),
    BX = base64char_encode(X),
    BY = base64char_encode(Y),
    BZ = base64char_encode(Z),
    io:format("~s~n", [Acc]),
    base64_encode(Rest, <<Acc/binary, BW, BX, BY, BZ>>).

hexchar_decode(X) when X >= $0 andalso X =< $9 -> X - $0;
hexchar_decode(X) when X >= $A andalso X =< $F -> X - $A + 10;
hexchar_decode(X) when X >= $a andalso X =< $f -> X - $a + 10.

base64char_encode(X) when X >= 0 andalso X < 26 -> X + $A;
base64char_encode(X) when X >= 26 andalso X < 52 -> X - 26 + $a;
base64char_encode(X) when X >= 52 andalso X < 62 -> X - 52 + $0;
base64char_encode(62) -> $+;
base64char_encode(63) -> $/.
