open Core
open Utils
open Crypto_providers

module Covercrypt_msk
    (Conf : sig
      val lambda : int
    end)
    (S : Signature)
    (M : MAC)
    (H1 : Hash)                 (* outputs 1 * lambda bits *)
    (H2 : Hash)                 (* outputs 2 * lambda bits *)
    (Nike : KH_NIKE)
    (Kem : KEM)
    (Right : sig
      type t
    end) =
struct
  (* A tracing level set to 0 does not allow tracing colluding users, but
     guarantees use secret keys are unique. *)
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

  and enc = { tracing : Nike.Pk.t list; renc : renc }

  and _ tk =
    | Secret : Nike.Sk.t list -> secret tk
    | Public : Nike.Pk.t list -> public tk

  and _ elt =
    | NP : Nike.Pk.t -> public elt
    | NS : Nike.Sk.t -> secret elt
    | NE : string -> encaps elt
    | KP : Kem.ek -> public elt
    | KS : Kem.dk -> secret elt
    | KE : string * Kem.enc -> encaps elt
    | HS : Nike.Sk.t * Kem.dk -> secret elt
    | HP : Nike.Pk.t * Kem.ek -> public elt
    | HE : { nss : string; kss : string; enc : Kem.enc } -> encaps elt

  and renc =
    | NEnc of string
    | KEnc of (string * Kem.enc)
    | HEnc of (string * Kem.enc)

  let rec check_homogeneity =
    let check e1 e2 =
      match (e1, e2) with
      | NP _, NP _ | KP _, KP _ | HP _, HP _ -> ()
      | _, _ -> invalid_arg "heterogeneous elements"
    in
    function elt :: elts -> List.iter (check elt) elts | _ -> ()

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

  let keygen rng msk policy =
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

  let encaps rng (mpk : mpk) policy =
    let seed, sk =
      let module Rng = (val rng : RNG) in
      let rec loop () =
        let seed = Rng.draw Conf.lambda in
        (* TODO: we need the guarantee that dimensions are compatible to prevent
           infinite loops. *)
        match Nike.Sk.of_string (H1.hash seed) with
        | Some sk -> (seed, sk)
        | None -> loop ()
      in
      loop ()
    in
    let tenc =
      let (Public tk) = mpk.tk in
      List.map (fun pk -> Nike.op pk sk) tk
    in
    let u_hash, renc =
      let random = Nike.Sk.random rng in
      let rbytes = Nike.Sk.to_string random in
      let p_elts = List.filter_map (Hashtbl.find_opt mpk.rk) policy in
      let _ = check_homogeneity p_elts in
      let encs =
        shuffle rng
        @@ List.map
             (function
               | NP pk -> NE (Nike.op pk random |> Nike.Pk.to_string)
               | KP ek ->
                   let ss, enc = Kem.encaps rng ek in
                   xor_in_place ~dest:ss rbytes;
                   KE (Bytes.to_string ss, enc)
               | HP (pk, ek) ->
                   let nss = Nike.op pk random |> Nike.Pk.to_string in
                   let kss, enc = Kem.encaps rng ek in
                   xor_in_place ~dest:kss rbytes;
                   HE { nss; kss = Bytes.to_string kss; enc })
             p_elts
      in
      let t_hash =
        H1.hash
        @@ String.cat
             (String.concat "" (List.map Nike.Pk.to_string tenc))
             (String.concat ""
             @@ List.filter_map
                  (function
                    | KE (_, enc) -> Some (Kem.Encapsulation.to_string enc)
                    | HE { enc; _ } -> Some (Kem.Encapsulation.to_string enc)
                    | NE _ -> None)
                  encs)
      in
      (* TODO: why keeping both pt and ss for hybridized elements? *)
      let encs =
        List.map
          (function
            | NE nss ->
                let bytes =
                  H1.hash @@ String.concat "" [ nss; t_hash ] |> Bytes.of_string
                in
                xor_in_place ~dest:bytes seed;
                NEnc (Bytes.to_string bytes)
            | KE (kss, enc) ->
                let bytes =
                  H1.hash @@ String.concat "" [ kss; t_hash ] |> Bytes.of_string
                in
                xor_in_place ~dest:bytes seed;
                KEnc (Bytes.to_string bytes, enc)
            | HE { nss; kss; enc } ->
                let bytes =
                  H1.hash @@ String.concat "" [ nss; kss; t_hash ]
                  |> Bytes.of_string
                in
                xor_in_place ~dest:bytes seed;
                HEnc (Bytes.to_string bytes, enc))
          encs
      in
      let u_hash =
        H1.hash
        @@ String.concat ""
             (t_hash
             :: List.map
                  (function
                    | NEnc enc -> enc | KEnc (enc, _) | HEnc (enc, _) -> enc)
                  encs)
      in
      (u_hash, encs)
    in
    let j_hash = H2.hash (seed ^ u_hash) in
    let key = String.sub j_hash 0 Conf.lambda in
    let tag = String.sub j_hash Conf.lambda Conf.lambda in
    (key, tag, tenc, renc)
end
