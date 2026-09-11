open Core
open Utils

module S
    (Right : sig
      include Stdlib.Map.OrderedType

      val to_bytes : t -> bytes
    end)
    (Nike : NIKE)
    (Kem : KEM)
    (Sig : Signature)
    (G : sig
      val hash : bytes -> Nike.sk
    end)
    (T : sig
      type t

      val hash : Kem.enc list -> t
    end)
    (U : sig
      type t

      val hash : bytes list -> t:T.t -> t
    end)
    (H : sig
      val hash : Nike.key -> Kem.key -> c1:Nike.pk -> c2:Nike.pk -> T.t -> bytes
    end)
    (J : sig
      type key
      type tag

      val hash : secret:bytes -> c1:Nike.pk -> c2:Nike.pk -> U.t -> key * tag
    end)
    () : KEM_AC = struct
  module RightMM = MakeMM (Right) ()
  module RightMap = MakeMap (Right) ()
  module Universe = MakeSet (Right) ()
  module Policy = MakeSet (Right) ()

  type right = Right.t
  type universe = Universe.t
  type policy = Policy.t
  type key = J.key
  type tag = J.tag

  type msk = {
    v : nat;
    s : Nike.sk;
    s1 : Nike.sk;
    s2 : Nike.sk;
    sk : Sig.sk;
    rsk : (Nike.sk * Kem.dk) RightMM.t;
  }

  type mpk = {
    v : nat;
    h : Nike.pk;
    h1 : Nike.pk;
    h2 : Nike.pk;
    rpk : (Nike.pk * Kem.ek) RightMap.t;
    seal : Sig.seal;
  }

  type usk = {
    v : nat;
    u1 : Nike.sk;
    u2 : Nike.sk;
    h1 : Nike.pk;
    h2 : Nike.pk;
    vk : Sig.vk;
    rsk : (Nike.sk * Kem.dk) RightMM.t;
    seal : Sig.seal;
  }

  type enc = {
    v : nat;
    tag : tag;
    c1 : Nike.pk;
    c2 : Nike.pk;
    xenc : (Kem.enc * bytes) list;
  }

  let rpk_to_bytes rpk =
    RightMap.fold
      (fun right (pk, ek) bytes ->
        Right.to_bytes right :: Nike.pk_to_bytes pk :: Kem.ek_to_bytes ek
        :: bytes)
      rpk []

  let rsk_to_bytes rsk =
    RightMM.fold
      (fun right keys bytes ->
        Right.to_bytes right
        :: NonEmptyList.fold_right
             (fun (sk, dk) bytes ->
               Nike.sk_to_bytes sk :: Kem.dk_to_bytes dk :: bytes)
             keys bytes)
      rsk []

  let int32_to_le_bytes n =
    let bytes = Bytes.create 4 in
    Bytes.set_int32_le bytes 0 n;
    bytes

  let int32_of_le_bytes bytes = Bytes.get_int32_le bytes 0

  let sign_mpk ~sk ~v ~h ~h1 ~h2 ~rpk =
    let h = Nike.pk_to_bytes h in
    let h1, h2 = (Nike.pk_to_bytes h1, Nike.pk_to_bytes h2) in
    let bytes = Nat.to_bytes v :: h :: h1 :: h2 :: rpk_to_bytes rpk in
    Sig.sign sk ~msg:(Bytes.concat Bytes.empty bytes)

  let is_valid_mpk vk mpk =
    let h = Nike.pk_to_bytes mpk.h in
    let h1, h2 = (Nike.pk_to_bytes mpk.h1, Nike.pk_to_bytes mpk.h2) in
    let v = Nat.to_bytes mpk.v in
    let bytes = v :: h :: h1 :: h2 :: rpk_to_bytes mpk.rpk in
    Sig.verify vk mpk.seal ~msg:(Bytes.concat Bytes.empty bytes)

  let sign_usk ~sk ~v ~u1 ~u2 ~h1 ~h2 ~rsk =
    let u1, u2 = (Nike.sk_to_bytes u1, Nike.sk_to_bytes u2) in
    let h1, h2 = (Nike.pk_to_bytes h1, Nike.pk_to_bytes h2) in
    let bytes = Nat.to_bytes v :: u1 :: u2 :: h1 :: h2 :: rsk_to_bytes rsk in
    Sig.sign sk ~msg:(Bytes.concat Bytes.empty bytes)

  let is_valid_usk (msk : msk) (usk : usk) =
    let v = Nat.to_bytes usk.v in
    let u1, u2 = (Nike.sk_to_bytes usk.u1, Nike.sk_to_bytes usk.u2) in
    let h1, h2 = (Nike.pk_to_bytes usk.h1, Nike.pk_to_bytes usk.h2) in
    let bytes = v :: u1 :: u2 :: h1 :: h2 :: rsk_to_bytes usk.rsk in
    Sig.verify (Sig.get_vk msk.sk) usk.seal
      ~msg:(Bytes.concat Bytes.empty bytes)

  let get_mpk (msk : msk) =
    let v = msk.v in
    let h = Nike.get_pk msk.s in
    let h1, h2 = (Nike.get_pk msk.s1, Nike.get_pk msk.s2) in
    let rpk =
      RightMM.fold
        (fun r secrets ->
          let sk, dk = NonEmptyList.head secrets in
          RightMap.add r (Nike.get_pk sk, Kem.get_ek dk))
        msk.rsk RightMap.empty
    in
    { v; h; h1; h2; rpk; seal = sign_mpk ~sk:msk.sk ~v ~h ~h1 ~h2 ~rpk }

  let setup rng universe =
    let msk =
      let v = Nat.Any Nat.Zero in
      let s = Nike.gen_sk rng in
      let s1, s2 = (Nike.gen_sk rng, Nike.gen_sk rng) in
      let sk = Sig.gen_sk rng in
      let rsk =
        Universe.fold
          (fun r rsk -> RightMM.add r (Nike.gen_sk rng, Kem.gen_dk rng) rsk)
          universe RightMM.empty
      in
      { v; s; s1; s2; sk; rsk }
    in
    (msk, get_mpk msk)

  let keygen rng msk policy =
    let u1 = Nike.gen_sk rng in
    let u2 = Nike.Scalar.((msk.s - (u1 * msk.s1)) / msk.s2) in
    let h1, h2 = (Nike.get_pk msk.s1, Nike.get_pk msk.s2) in
    let vk = Sig.get_vk msk.sk in
    let rsk =
      Policy.fold
        (fun r ->
          match RightMM.get msk.rsk r with
          | None -> invalid_arg "invalid policy"
          | Some secrets -> RightMM.add r (NonEmptyList.head secrets))
        policy msk.rsk
    in
    let v = msk.v in
    let seal = sign_usk ~sk:msk.sk ~v ~u1 ~u2 ~h1 ~h2 ~rsk in
    { v; u1; u2; h1; h2; vk; rsk; seal }

  let encaps rng mpk policy =
    let secret = gen_bytes rng 32 in
    let r = G.hash secret in
    let tmp_encs =
      shuffle rng
      @@ Policy.fold
           (fun right tmp_encs ->
             let pk, ek =
               match RightMap.get mpk.rpk right with
               | Some (pk, ek) -> (pk, ek)
               | None -> invalid_arg "invalid policy"
             in
             let k = Nike.session_key pk r in
             let k', enc = Kem.encaps rng ek in
             (k, k', enc) :: tmp_encs)
           policy []
    in
    let c1 = Nike.(r * mpk.h1) in
    let c2 = Nike.(r * mpk.h2) in
    let t = T.hash @@ List.map (fun (_, _, enc) -> enc) tmp_encs in
    let xenc =
      List.map
        (fun (k, k', e) ->
          let f = xor secret @@ H.hash k k' ~c1 ~c2 t in
          (e, f))
        tmp_encs
    in
    let key, tag =
      let u = U.hash ~t @@ List.map (fun (_, f) -> f) xenc in
      J.hash ~secret ~c1 ~c2 u
    in
    (key, { v = mpk.v; tag; c1; c2; xenc })

  let usk_secrets usk =
    interleave @@ List.of_seq
    @@ Seq.map NonEmptyList.to_list
    @@ RightMM.to_val_seq usk.rsk

  let try_decaps enc p h1 h2 t u sk dk e f =
    match Kem.decaps dk e with
    | None -> None
    | Some k' ->
        let k = Nike.session_key p sk in
        let secret = xor f @@ H.hash k k' ~c1:enc.c1 ~c2:enc.c2 t in
        let key, tag = J.hash ~secret ~c1:enc.c1 ~c2:enc.c2 u in
        if tag = enc.tag then
          let r = G.hash secret in
          let c1 = Nike.(r * h1) in
          let c2 = Nike.(r * h2) in
          if enc.c1 = c1 && enc.c2 = c2 then Some key else None
        else None

  let decaps usk enc =
    let p1 = Nike.(usk.u1 * enc.c1) in
    let p2 = Nike.(usk.u2 * enc.c2) in
    let p = Nike.Point.(p1 + p2) in
    let t = T.hash @@ List.map (fun (e, _) -> e) enc.xenc in
    let u = U.hash ~t @@ List.map (fun (_, f) -> f) enc.xenc in
    List.fold_left
      (fun key (sk, dk) ->
        List.fold_right
          (fun (e, f) -> function
            | None -> try_decaps enc p usk.h1 usk.h2 t u sk dk e f
            | Some key -> Some key)
          enc.xenc key)
      None (usk_secrets usk)

  let msk_secrets (msk : msk) =
    (* TODO: once a key in a history has opened the encapsulation, other keys
         from the same history need to attempt opening it again. *)
    interleave @@ List.of_seq
    @@ Seq.map (fun (r, secrets) ->
        List.map (fun (sk, dk) -> (r, sk, dk)) (NonEmptyList.to_list secrets))
    @@ RightMM.to_seq msk.rsk

  let enc_policy msk enc =
    let p1 = Nike.(enc.c1) in
    let p2 = Nike.(Scalar.((msk.s - msk.s1) / msk.s2) * enc.c2) in
    let h1 = Nike.get_pk msk.s1 in
    let h2 = Nike.get_pk msk.s2 in
    let p = Nike.Point.(p1 + p2) in
    let t = T.hash @@ List.map (fun (e, _) -> e) enc.xenc in
    let u = U.hash ~t @@ List.map (fun (_, f) -> f) enc.xenc in
    List.fold_left
      (fun acc (r, sk, dk) ->
        List.fold_left
          (fun acc (e, f) ->
            match (try_decaps enc p h1 h2 t u sk dk e f, acc) with
            | None, acc -> acc
            | Some key, None -> Some (key, Policy.add r Policy.empty)
            | Some key, Some (key', policy) ->
                if key = key' then Some (key, Policy.add r policy)
                else invalid_arg "invalid encapsulation")
          acc enc.xenc)
      None
    @@ msk_secrets msk

  let enc_refresh rng msk mpk enc =
    if not (is_valid_mpk (Sig.get_vk msk.sk) mpk) then
      invalid_arg "invalid master public key"
    else if msk.v != mpk.v then invalid_arg "outdated master public key"
    else
      enc_policy msk enc
      |> Option.map (fun (old_key, policy) ->
          let new_key, enc = encaps rng mpk policy in
          (~old_key, ~new_key, enc))

  let msk_revision (msk : msk) = msk.v
  let mpk_revision (mpk : mpk) = mpk.v
  let usk_revision (usk : usk) = usk.v
  let enc_revision (enc : enc) = enc.v

  let usk_policy usk =
    RightMM.fold (fun r _ -> Policy.add r) usk.rsk Policy.empty

  let rotate rng (msk : msk) policy =
    let v = Nat.succ msk.v in
    let rsk =
      Policy.fold
        (fun r -> RightMM.add r (Nike.gen_sk rng, Kem.gen_dk rng))
        policy msk.rsk
    in
    { msk with v; rsk }

  let usk_refresh (msk : msk) usk keep_old_secrets =
    if not (is_valid_usk msk usk) then invalid_arg "invalid user secret key"
    else
      let v = msk.v in
      let rsk =
        RightMM.fold
          (fun r secrets rsk ->
            match RightMM.get msk.rsk r with
            | None -> rsk
            | Some master_secrets ->
                if keep_old_secrets then
                  let newer_secrets =
                    NonEmptyList.take_while
                      (fun s -> s != NonEmptyList.head secrets)
                      master_secrets
                  in
                  RightMM.set r
                    (NonEmptyList.append_list newer_secrets secrets)
                    rsk
                else RightMM.add r (NonEmptyList.head master_secrets) rsk)
          usk.rsk RightMM.empty
      in
      let seal =
        sign_usk ~sk:msk.sk ~v:usk.v ~u1:usk.u1 ~u2:usk.u2 ~h1:usk.h1 ~h2:usk.h2
          ~rsk
      in
      { usk with v; rsk; seal }
end
