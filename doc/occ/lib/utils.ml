open Core

let shuffle (module Rng : RNG) = List.sort (fun _ _ -> (Rng.next () mod 2) - 1)
let gen_bytes (module Rng : RNG) = Rng.gen

(** Flattens the given lists into a single lists which values alternatively come
    from each of those lists. *)
let interleave (values : 'v list list) : 'v list =
  let rec loop acc = function
    | [], [] -> List.rev acc
    | [], rhs -> loop acc (List.rev rhs, [])
    | [] :: lhs, rhs -> loop acc (lhs, rhs)
    | (secrets :: more_secrets) :: lhs, rhs ->
        loop (secrets :: acc) (lhs, more_secrets :: rhs)
  in
  loop [] (values, [])

let xor b1 b2 =
  let length =
    if Bytes.length b1 = Bytes.length b2 then Bytes.length b1
    else invalid_arg "byte-strings of different lengts"
  in
  Bytes.init length (fun i ->
      let c1 = Bytes.get b1 i |> Char.code in
      let c2 = Bytes.get b2 i |> Char.code in
      Int.logxor c1 c2 |> Char.chr)
