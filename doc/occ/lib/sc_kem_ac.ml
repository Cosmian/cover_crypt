open Core
open Utils

module type Right = sig
  include Stdlib.Map.OrderedType
  include Serializable with type t := t
end

module S (Right : Right) (Provider : Crypto_provider.S) () : KEM_AC = struct
  include Provider
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
    rsk : (Nike.sk * Kem.dk) RightMM.t;
  }

  type mpk = {
    v : nat;
    h : Nike.pk;
    h1 : Nike.pk;
    h2 : Nike.pk;
    rpk : (Nike.pk * Kem.ek) RightMap.t;
  }

  type usk = {
    v : nat;
    u1 : Nike.sk;
    u2 : Nike.sk;
    h1 : Nike.pk;
    h2 : Nike.pk;
    vk : Signature.vk;
    rsk : (Nike.sk * Kem.dk) RightMM.t;
  }

  type enc = {
    v : nat;
    tag : tag;
    c1 : Nike.pk;
    c2 : Nike.pk;
    xenc : (Kem.enc * Otp.ctx) list;
  }

  type 'a signer = Signer : 'a * Signature.sk -> 'a signer
  type 'a opener = Opener : 'a * Signature.vk -> 'a opener
  type 'a sealed = Sealed : 'a * Signature.seal -> 'a sealed

  let promote (Signer (_, sk)) t = Opener (t, Signature.get_vk sk)
  let demote (Signer (t, sk)) = Opener (t, Signature.get_vk sk)
  let to_raw (Opener (t, _)) = t

  let seal rng to_bytes (Signer (_, sk)) t =
    Sealed (t, Signature.sign rng sk ~msg:(to_bytes t))

  let auto_verify to_bytes (Sealed (Opener (t, vk), seal)) =
    if Signature.verify vk ~msg:(to_bytes t) seal then Some t else None

  let verify to_bytes (Opener (_, vk)) (Sealed (t, seal)) =
    if Signature.verify vk ~msg:(to_bytes t) seal then Some t else None

  type _ cc_obj =
    | MSK : msk -> msk cc_obj
    | MPK : mpk -> mpk cc_obj
    | USK : usk -> usk cc_obj
    | ENC : enc -> enc cc_obj

  type any = Any : _ cc_obj -> any

  let version = function
    | Any (MSK { v }) -> v
    | Any (MPK { v }) -> v
    | Any (USK { v }) -> v
    | Any (ENC { v }) -> v

  let serialize =
    let rsk_to_bytes rsk =
      RightMM.fold
        (fun right keys bytes ->
          List.cons (Right.to_bytes right)
          @@ NonEmptyList.fold_right
               (fun (sk, dk) bytes ->
                 Nike.Sk.to_bytes sk :: Kem.Dk.to_bytes dk :: bytes)
               keys bytes)
        rsk []
    in
    let rpk_to_bytes rpk =
      RightMap.fold
        (fun right (pk, ek) bytes ->
          let right = Right.to_bytes right in
          let pk = Nike.Pk.to_bytes pk in
          let ek = Kem.Ek.to_bytes ek in
          right :: pk :: ek :: bytes)
        rpk []
    in
    function
    | Any (MSK msk) ->
        let v = Nat.to_bytes msk.v in
        let h = Nike.Sk.to_bytes msk.s in
        let h1, h2 = (Nike.Sk.to_bytes msk.s1, Nike.Sk.to_bytes msk.s2) in
        let bytes = v :: h :: h1 :: h2 :: rsk_to_bytes msk.rsk in
        Bytes.concat Bytes.empty bytes
    | Any (MPK mpk) ->
        let v = Nat.to_bytes mpk.v in
        let h = Nike.Pk.to_bytes mpk.h in
        let h1, h2 = (Nike.Pk.to_bytes mpk.h1, Nike.Pk.to_bytes mpk.h2) in
        let rpk = rpk_to_bytes mpk.rpk in
        Bytes.concat Bytes.empty (v :: h :: h1 :: h2 :: rpk)
    | Any (USK usk) ->
        let v = Nat.to_bytes usk.v in
        let u1, u2 = (Nike.Sk.to_bytes usk.u1, Nike.Sk.to_bytes usk.u2) in
        let h1, h2 = (Nike.Pk.to_bytes usk.h1, Nike.Pk.to_bytes usk.h2) in
        let bytes = v :: u1 :: u2 :: h1 :: h2 :: rsk_to_bytes usk.rsk in
        Bytes.concat Bytes.empty bytes
    | Any (ENC enc) ->
        let v = Nat.to_bytes enc.v in
        let tag = SBytes.to_bytes enc.tag in
        let c1, c2 = (Nike.Pk.to_bytes enc.c1, Nike.Pk.to_bytes enc.c2) in
        let xenc =
          List.fold_right
            (fun ((enc : Kem.enc), (mask : Otp.ctx)) bytes ->
              SBytes.to_bytes (enc :> Kem.e sbytes)
              :: SBytes.to_bytes (mask :> keylen sbytes)
              :: bytes)
            enc.xenc []
        in
        let bytes = v :: tag :: c1 :: c2 :: xenc in
        Bytes.concat Bytes.empty bytes

  let mpk_to_bytes mpk = serialize (Any (MPK mpk))
  let usk_to_bytes usk = serialize (Any (USK usk))

  let setup rng universe =
    let v = Nat.Any Nat.zero in
    let s = Nike.gen_sk rng in
    let s1, s2 = (Nike.gen_sk rng, Nike.gen_sk rng) in
    let rsk =
      Universe.fold
        (fun r -> RightMM.add r (Nike.gen_sk rng, Kem.gen_dk rng))
        universe RightMM.empty
    in
    Signer ({ v; s; s1; s2; rsk }, Signature.gen_sk rng)

  let gen_pk rng msk (policy : policy) =
    let mpk =
      let (Signer (msk, _)) = msk in
      let h = Nike.gen_pk msk.s in
      let h1, h2 = (Nike.gen_pk msk.s1, Nike.gen_pk msk.s2) in
      let rpk =
        RightMM.fold
          (fun r secrets ->
            let sk, dk = NonEmptyList.head secrets in
            RightMap.add r (Nike.gen_pk sk, Kem.get_ek dk))
          msk.rsk RightMap.empty
      in
      { v = msk.v; h; h1; h2; rpk }
    in
    seal rng mpk_to_bytes msk mpk

  let keygen rng msk policy =
    let usk =
      let (Signer (msk, sk)) = msk in
      let u1 = Nike.gen_sk rng in
      let u2 = Nike.Sk.((msk.s - (u1 * msk.s1)) / msk.s2) in
      let h1, h2 = (Nike.gen_pk msk.s1, Nike.gen_pk msk.s2) in
      let vk = Signature.get_vk sk in
      let rsk =
        Policy.fold
          (fun r ->
            match RightMM.get msk.rsk r with
            | None -> invalid_arg "invalid policy"
            | Some secrets -> RightMM.add r (NonEmptyList.head secrets))
          policy msk.rsk
      in
      { v = msk.v; u1; u2; h1; h2; vk; rsk }
    in
    seal rng usk_to_bytes msk usk

  let encaps rng mpk policy =
    let pks =
      Policy.fold
        (fun right acc ->
          match RightMap.get mpk.rpk right with
          | Some (pk, ek) -> (pk, ek) :: acc
          | None -> invalid_arg "invalid policy")
        policy []
    in
    let secret = SBytes.gen rng keylen in
    let r = G.hash secret in
    let c1 = Nike.(r * mpk.h1) in
    let c2 = Nike.(r * mpk.h2) in
    let encs =
      shuffle rng
      @@ List.map
           (fun (pk, ek) ->
             let k = Nike.session_key pk r in
             let k', enc = Kem.encaps rng ek in
             (k, k', enc))
           pks
    in
    let t = T.hash @@ List.map (fun (_, _, e) -> e) encs in
    let xenc =
      List.map
        (fun (k, k', e) ->
          let h = H.hash k k' ~c1 ~c2 t in
          let f = Otp.mask h secret in
          (e, f))
        encs
    in
    let key, tag =
      let u = U.hash ~t @@ List.map Pair.snd xenc in
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
        let secret = Otp.unmask (H.hash k k' ~c1:enc.c1 ~c2:enc.c2 t) f in
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
    let p = Nike.Pk.(p1 + p2) in
    let t = T.hash @@ List.map (fun (e, _) -> e) enc.xenc in
    let u = U.hash ~t @@ List.map Pair.snd enc.xenc in
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
    let p2 = Nike.(Sk.((msk.s - msk.s1) / msk.s2) * enc.c2) in
    let h1 = Nike.gen_pk msk.s1 in
    let h2 = Nike.gen_pk msk.s2 in
    let p = Nike.Pk.(p1 + p2) in
    let t = T.hash @@ List.map (fun (e, _) -> e) enc.xenc in
    let u = U.hash ~t @@ List.map Pair.snd enc.xenc in
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

  let recaps rng (msk : msk) (mpk : mpk) enc =
    if msk.v == mpk.v then
      match enc_policy msk enc with
      | None -> invalid_arg "could not open encapsulation"
      | Some (old_key, policy) ->
          let new_key, enc = encaps rng mpk policy in
          (~old:old_key, new_key, enc)
    else invalid_arg "outdated master public key"

  let usk_policy usk =
    RightMM.fold (fun r _ -> Policy.add r) usk.rsk Policy.empty

  let rotate rng (Signer ((msk : msk), sk)) policy =
    let v = Nat.succ msk.v in
    let rsk =
      Policy.fold
        (fun r -> RightMM.add r (Nike.gen_sk rng, Kem.gen_dk rng))
        policy msk.rsk
    in
    Signer ({ msk with v; rsk }, sk)

  let update rng (msk : msk signer) usk ~keep_old =
    let usk =
      let (Signer (msk, sk)) = msk in
      let v = msk.v in
      let rsk =
        RightMM.fold
          (fun r secrets rsk ->
            match RightMM.get msk.rsk r with
            | None -> rsk
            | Some master_secrets ->
                if keep_old then
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
      { usk with v; rsk }
    in
    seal rng usk_to_bytes msk usk
end
