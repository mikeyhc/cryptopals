-module(cryptopals_block).

-export([pkcs7_padding/2]).

-spec pkcs7_padding(binary(), pos_integer()) -> binary().
pkcs7_padding(Message, BlockSize) ->
    PadLen = BlockSize - size(Message) rem BlockSize,
    Pad = list_to_binary(lists:duplicate(PadLen, PadLen)),
    <<Message/binary, Pad/binary>>.
