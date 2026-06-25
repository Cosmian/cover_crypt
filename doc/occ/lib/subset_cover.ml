open Core
open Crypto_providers

module Covercrypt_msk
    (S : Signature)
    (M : MAC)
    (Nike : KH_NIKE)
    (Kem : KEM)
    (Right : sig
      type t
    end) =
struct
  let t = 0

  type right = Right.t
  type kind = N | K | H
  type secret = Secret
  type public = Public
  type encaps = Encaps

  type msk = {
    rev : int;
    s : Nike.Sk.t;
    mk : M.key;
    sk : S.sk;
    tk : secret tk;
    rk : (Right.t, secret elt list) Hashtbl.t;
  }

  and mpk = {
    (* TODO (requires serialization) *)
    (* sgn : S.signature; *)
    rev : int;
    h : Nike.Pk.t;
    tk : public tk;
    rk : (Right.t, public elt) Hashtbl.t;
  }

  and usk = {
    (* TODO (requires serialization) *)
    (* tag : M.tag; *)
    rev : int;
    vk : S.vk;
    tk : secret tk;
    rk : (Right.t, secret elt list) Hashtbl.t;
  }

  and enc = { tracing : Nike.Pk.t list; rights : encaps elt list }

  and _ tk =
    | Secret : Nike.Sk.t list -> secret tk
    | Public : Nike.Pk.t list -> public tk

  and _ elt =
    | NP : Nike.Pk.t -> public elt
    | NS : Nike.Sk.t -> secret elt
    | NE : Nike.Pk.t -> encaps elt
    | KP : Kem.ek -> public elt
    | KS : Kem.dk -> secret elt
    | KE : bytes * Kem.enc -> encaps elt
    | HS : Nike.Sk.t * Kem.dk -> secret elt
    | HP : Nike.Pk.t * Kem.ek -> public elt
    | HE : bytes * Kem.enc -> encaps elt

  let setup rng universe =
    let rev = 0 in
    let mk = M.keygen rng in
    let sk, vk = S.keygen rng in
    let s, h = Nike.keygen rng in
    let tsk, tpk = List.init (t + 2) (fun _ -> Nike.keygen rng) |> List.split in
    let rsk, rpk =
      List.to_seq universe
      |> Seq.map (function
        | r, N ->
            let sk, pk = Nike.keygen rng in
            ((r, [ NS sk ]), (r, NP pk))
        | r, K ->
            let dk, ek = Kem.keygen rng in
            ((r, [ KS dk ]), (r, KP ek))
        | r, H ->
            let sk, pk = Nike.keygen rng in
            let dk, ek = Kem.keygen rng in
            ((r, [ HS (sk, dk) ]), (r, HP (pk, ek))))
      |> Seq.split
    in
    ( { rev; s; mk; sk; tk = Secret tsk; rk = Hashtbl.of_seq rsk },
      { rev; h; tk = Public tpk; rk = Hashtbl.of_seq rpk } )

  let keygen rng msk (policy : right list) =
    let tk =
      (*
         let y :: ys = tk with length tk = t + 2 in
         dot (x :: xs) (y :: ys) = s
         <=> x * y + dot xs ys = msk.s
         <=> x = (s - dot xs ys) / y
      *)
      let y, ys =
        let (Secret tk) = msk.tk in
        match tk with
        | [] -> invalid_arg "msk.tk is empty"
        | y :: ys ->
            if Nike.Sk.zero = y then invalid_arg "zero in msk.tk" else (y, ys)
      in
      let xs = List.init (t + 1) (fun _ -> Nike.keygen rng |> Pair.fst) in
      let x =
        Nike.Sk.(
          (msk.s - List.fold_left2 (fun a x y -> a + (x * y)) Nike.Sk.zero xs ys)
          / y)
        |> Option.get (* safe since y is not zero *)
      in
      x :: xs
    in
    let rk =
      List.to_seq policy
      |> Seq.filter_map (fun r ->
          Hashtbl.find_opt msk.rk r
          |> Option.map (List.take 1)
          |> Option.map (Pair.make r))
    in
    {
      rev = msk.rev;
      vk = S.derive msk.sk;
      tk = Secret tk;
      rk = Hashtbl.of_seq rk;
    }

  let encaps rng (mpk : mpk) (policy : right list) =
    let r = Nike.keygen rng |> Pair.fst in
    let r_bytes = Nike.Sk.to_bytes r in
    let _renc =
      List.to_seq policy
      |> Seq.filter_map (fun r -> Hashtbl.find_opt mpk.rk r)
      |> Seq.map (function
        | NP pk -> NE (Nike.op pk r)
        | KP ek ->
            let key, enc = Kem.encaps rng ek in
            xor_in_place ~dest:key r_bytes;
            KE (key, enc)
        | HP (pk, ek) ->
            let key, enc = Kem.encaps rng ek in
            xor_in_place ~dest:key (Nike.op pk r |> Nike.Pk.to_bytes);
            HE (key, enc))
      |> List.of_seq
    in
    ()
end
