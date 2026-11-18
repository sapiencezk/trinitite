::  jetcheck: Trinitite jet-vs-Hoon equivalence test kernel.
::
::  One poke, %go, builds the @rs door's add/sub/mul/div/lth cores *before*
::  any integer core with the same label, then the integer arithmetic, bit
::  and list cores, ++jam and ++shax, and the Tip5 arms 1499kernel's
::  ++digest calls (row 328 (d)) with ++digest itself. Under label-only
::  %fast binding the rs cores take the integer jets; under label +
::  parent-path binding they do not. The probe's poke-jetcheck step then
::  checks every registered jet against its Hoon. The rs operands are +0
::  so the rs arms stay cheap when they run as Nock.
::
::  A poke [%digest n] gives [%r (digest n)], ++digest of 1499kernel's
::  iec-types; [%digest-gulf k] gives [%r (digest ~[1 2 ... k])], a list
::  deeper than the lite node's cue admits. tests/tip5/run.py checks both
::  on the row 328 golden vectors.
::
/=  *  /common/zoon
/=  *  /common/wrapper
/=  types  /lib/iec-types
=>
|%
+$  versioned-state  $%([%0 n=@ud])
+$  effect  [%r p=*]
++  moat  (keep versioned-state)
--
%-  (moat &)
^-  fort:moat
|_  state=versioned-state
++  load
  |=  old=versioned-state
  ^-  versioned-state
  old
++  peek
  |=  arg=path
  ^-  (unit (unit *))
  ?:  =(arg /profile)  ~
  ``n.state
++  poke
  |=  =ovum:moat
  ^-  [(list effect) versioned-state]
  ?:  ?=([%digest-gulf @] cause.input.ovum)
    =/  i=@  +.cause.input.ovum
    =|  l=(list @)
    |-
    ?.  =(0 i)  $(i (dec i), l [i l])
    [~[[%r (digest:types l)]] state]
  ?:  ?=([%digest *] cause.input.ovum)
    [~[[%r (digest:types +.cause.input.ovum)]] state]
  =/  c  ((soft ,[%go ~]) cause.input.ovum)
  ?~  c  ~|("invalid cause" !!)
  =/  x  `@rs`0x0
  =/  y  `@rs`0x0
  =/  f
    :*  (~(add rs %n) x y)  (~(sub rs %n) y x)  (~(mul rs %n) x y)
        (~(div rs %n) x y)  (~(lth rs %n) x y)
    ==
  =/  i
    :*  (add 2 3)  (sub 5 3)  (mul 2 3)  (div 7 2)  (mod 7 2)  (dec 7)
        (lth 2 3)  (gth 2 3)  (lte 2 3)  (gte 2 3)
        (rsh 3 0x1234)  (rsh [3 1] 0x12.3456)  (lsh 3 0x12)
        (con 5 3)  (dis 5 3)  (mix 5 3)
        (lent ~[1 2 3])  (flop ~[1 2 3])  (weld ~[1 2] ~[3])
    ==
  =/  s  [(jam [1 2]) (shax 'abc')]
  =/  t
    :*  (permutation:tip5:z (reap 16 0))
        (hash-varlen:tip5:z ~[1 2 3])
        (hash-belts-list:tip5:z ~[1 2 3])
        (hash-ten-cell:tip5:z [[1 2 3 4 5] [6 7 8 9 10]])
        (hash-noun-varlen:tip5:z [1 2])
        (hash-hashable:tip5:z [%leaf 5])
        (digest-to-atom:tip5:z [1 2 3 4 5])
        (digest:types [1 2])
    ==
  [~[[%r [f i s t]]] state(n +(n.state))]
--
