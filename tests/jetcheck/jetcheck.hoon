::  jetcheck: Trinitite jet-vs-Hoon equivalence test kernel.
::
::  One poke, %go, builds the @rs door's add/sub/mul/div/lth cores *before*
::  any integer core with the same label, then the integer arithmetic, bit
::  and list cores. Under label-only %fast binding the rs cores take the
::  integer jets; under label + parent-path binding they do not. The probe's
::  poke-jetcheck step then checks every registered jet against its Hoon.
::  The rs operands are +0 so the rs arms stay cheap when they run as Nock.
::
/=  *  /common/zoon
/=  *  /common/wrapper
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
  [~[[%r [f i]]] state(n +(n.state))]
--
