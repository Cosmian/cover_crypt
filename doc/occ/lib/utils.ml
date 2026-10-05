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
