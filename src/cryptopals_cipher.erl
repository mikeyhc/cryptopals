-module(cryptopals_cipher).

-export([single_xor/1]).

char_scores() ->
    #{$a =>  8.5, $b =>  2.1, $c =>  4.5, $d =>  3.4,
      $e => 11.1, $f =>  1.8, $g =>  2.5, $h =>  3.0,
      $i =>  7.5, $j =>  0.2, $k =>  1.1, $l =>  5.5,
      $m =>  3.0, $n =>  6.7, $o =>  7.1, $p =>  3.2,
      $q =>  0.2, $r =>  7.6, $s =>  5.7, $t =>  7.0,
      $u =>  3.6, $v =>  1.0, $w =>  1.3, $x =>  0.3,
      $y =>  1.8, $z =>  0.3}.

single_xor(Bytes) ->
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
    {Bit, Text, _Score} = lists:foldl(F, XorChar(0), lists:seq(16#1, 16#ff)),
    {Bit, Text}.

score_text(T) ->
    CharTable = char_scores(),
    score_text(T, CharTable, 0).

score_text(<<>>, _CharTable, Score) -> Score;
score_text(<<X, T/binary>>, CharTable, Score) ->
    V = maps:get(X, CharTable, 0),
    score_text(T, CharTable, Score + V).
