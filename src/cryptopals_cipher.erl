-module(cryptopals_cipher).

-export([single_xor/1, find_xor_string/1, repeating_key_xor/2]).

char_scores() ->
    #{$a =>  8.5, $b =>  2.1, $c =>  4.5, $d =>  3.4,
      $e => 11.1, $f =>  1.8, $g =>  2.5, $h =>  3.0,
      $i =>  7.5, $j =>  0.2, $k =>  1.1, $l =>  5.5,
      $m =>  3.0, $n =>  6.7, $o =>  7.1, $p =>  3.2,
      $q =>  0.2, $r =>  7.6, $s =>  5.7, $t =>  7.0,
      $u =>  3.6, $v =>  1.0, $w =>  1.3, $x =>  0.3,
      $y =>  1.8, $z =>  0.3}.

-spec single_xor(binary()) -> {byte(), binary()}.
single_xor(Bytes) ->
    {Bit, Text, _Score} = determine_best_byte(Bytes),
    {Bit, Text}.

-spec find_xor_string([binary()]) -> {byte(), binary()}.
find_xor_string([H|T]) ->
    F = fun({_, _, NewScore}=New, {_,_, OldScore}=Old) ->
                if NewScore > OldScore -> New;
                   true -> Old
                end
        end,
    {Bit, Text, _} = lists:foldl(
                       F,
                       determine_best_byte(H),
                       lists:map(fun determine_best_byte/1, T)
                      ),
    {Bit, Text}.

-spec repeating_key_xor(binary(), binary()) -> binary().
repeating_key_xor(Key, Input) ->
    Cipher = generate_key_cipher(Key, size(Input)),
    F = fun({A, B}, Acc) -> <<Acc/binary, (A bxor B)>> end,
    lists:foldl(F, <<>>, lists:zip(binary:bin_to_list(Input),
                                   binary:bin_to_list(Cipher))).

determine_best_byte(Bytes) ->
    Len = size(Bytes),
    XorChar = fun(C) ->
                BitStr = binary:list_to_bin(lists:duplicate(Len, C)),
                Xord = cryptopals_bytes:fixed_xor(Bytes, BitStr),
                {C, Xord, score_text(Xord)}
              end,
    F = fun(C, Old={_, _, OldScore}) ->
                New = XorChar(C),
                {_, _, NewScore} = New,
                if NewScore > OldScore -> New;
                   true -> Old
                end
        end,
    lists:foldl(F, XorChar(0), lists:seq(16#1, 16#ff)).

score_text(T) ->
    CharTable = char_scores(),
    score_text(T, CharTable, 0).

score_text(<<>>, _CharTable, Score) -> Score;
score_text(<<X, T/binary>>, CharTable, Score) ->
    V = maps:get(X, CharTable, 0),
    score_text(T, CharTable, Score + V).

generate_key_cipher(Key, Len) ->
    Size = size(Key),
    Count = Len div Size,
    Rem = Len rem Size,
    Partial = lists:duplicate(Count, Key),
    Full = Partial ++ [binary:part(Key, 0, Rem)],
    lists:foldl(fun(A, B) -> <<B/binary, A/binary>> end, <<>>, Full).
