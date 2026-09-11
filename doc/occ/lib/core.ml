module Nat = struct
  type z = Z
  type 'a s = S of 'a
  type 'a t = Zero : z t | More : 'a t -> 'a s t
  type any = Any : 'a t -> any

  let succ (Any n) = Any (More n)
  let rec size = function Any Zero -> 0 | Any (More n) -> 1 + size (Any n)

  let to_bytes n =
    let rec loop = function
      | Any Zero -> Z.zero
      | Any (More n) -> Z.succ @@ loop (Any n)
    in
    String.to_bytes @@ Z.to_bits @@ loop n
end

type nat = Nat.any

module NonEmptyList : sig
  type 'v t

  val init : 'v -> 'v t
  val cons : 'v -> 'v t -> 'v t
  val head : 'v t -> 'v
  val to_list : 'v t -> 'v list
  val take_while : ('v -> bool) -> 'v t -> 'v list
  val append_list : 'v list -> 'v t -> 'v t
  val fold_right : ('v -> 'acc -> 'acc) -> 'v t -> 'acc -> 'acc
end = struct
  type 'v t = 'v list

  let init a = a :: []
  let cons a b = a :: b
  let head = List.hd
  let to_list = Fun.id
  let take_while = List.take_while
  let append_list = List.append
  let fold_right = List.fold_right
end

module MakeSet (Key : Stdlib.Set.OrderedType) () : sig
  include Stdlib.Set.S with type elt = Key.t

  val contains : t -> Key.t -> bool
end = struct
  include Stdlib.Set.Make (Key)

  let contains s r = mem r s
end

module MakeMM (Key : Stdlib.Set.OrderedType) () : sig
  type 'v t

  val empty : 'v t
  val get : 'v t -> Key.t -> 'v NonEmptyList.t option
  val add : Key.t -> 'v -> 'v t -> 'v t
  val set : Key.t -> 'v NonEmptyList.t -> 'v t -> 'v t
  val map : (Key.t -> 'v NonEmptyList.t -> 'v NonEmptyList.t) -> 'v t -> 'v t

  val fold :
    (Key.t -> 'v NonEmptyList.t -> 'acc -> 'acc) -> 'v t -> 'acc -> 'acc

  val to_seq : 'v t -> (Key.t * 'v NonEmptyList.t) Seq.t
  val to_val_seq : 'v t -> 'v NonEmptyList.t Seq.t
end = struct
  module Map = Stdlib.Map.Make (Key)

  type 'v t = MM of 'v NonEmptyList.t Map.t

  let empty = MM Map.empty
  let get (MM m) k = Map.find_opt k m

  let add k v (MM m) =
    match Map.find_opt k m with
    | None -> MM (Map.add k (NonEmptyList.init v) m)
    | Some vs -> MM (Map.add k (NonEmptyList.cons v vs) m)

  let set k vs (MM m) = MM (Map.add k vs m)
  let fold f (MM m) a = Map.fold f m a

  let map f m =
    let (MM m) = m in
    MM (Map.fold (fun r vs -> Map.add r (f r vs)) m Map.empty)

  let to_seq (MM m) = Map.to_seq m
  let to_val_seq m = to_seq m |> Seq.map Pair.snd
end

module MakeMap (Key : Stdlib.Set.OrderedType) () : sig
  type 'v t

  val empty : 'v t
  val get : 'v t -> Key.t -> 'v option
  val add : Key.t -> 'v -> 'v t -> 'v t
  val fold : (Key.t -> 'v -> 'acc -> 'acc) -> 'v t -> 'acc -> 'acc
  val to_val_seq : 'v t -> 'v Seq.t
end = struct
  module Map = Stdlib.Map.Make (Key)

  type 'v t = M of 'v Map.t

  let empty = M Map.empty
  let get (M m) k = Map.find_opt k m
  let add k v (M m) = M (Map.add k v m)
  let fold f (M m) a = Map.fold f m a
  let to_val_seq (M m) = Map.to_seq m |> Seq.map Pair.snd
end

module type RNG = sig
  val gen : int -> bytes
  val next : unit -> int
end

module type Hash = sig
  val hash : bytes -> bytes
end

module type KEM = sig
  type dk
  type ek
  type enc
  type key

  val gen_dk : (module RNG) -> dk
  val get_ek : dk -> ek
  val encaps : (module RNG) -> ek -> key * enc
  val decaps : dk -> enc -> key option
  val dk_to_bytes : dk -> bytes
  val ek_to_bytes : ek -> bytes
  val ss_to_bytes : key -> bytes
  val enc_to_bytes : enc -> bytes
end

module type Group = sig
  type t

  val zero : t
  val ( + ) : t -> t -> t
  val ( - ) : t -> t -> t
end

module type Field = sig
  include Group

  val one : t
  val ( * ) : t -> t -> t
  val ( / ) : t -> t -> t
end

module type NIKE = sig
  module Point : Group
  module Scalar : Field

  type pk = Point.t
  type sk = Scalar.t
  type key

  val ( * ) : sk -> pk -> pk
  val gen_sk : (module RNG) -> sk
  val get_pk : sk -> pk
  val session_key : pk -> sk -> key
  val sk_to_bytes : sk -> bytes
  val pk_to_bytes : pk -> bytes
  val sk_of_bytes : bytes -> sk option
  val pk_of_bytes : bytes -> pk option
end

module type KEM_AC = sig
  type msk
  type mpk
  type usk
  type enc
  type key
  type universe
  type policy

  val setup : (module RNG) -> universe -> msk * mpk
  val keygen : (module RNG) -> msk -> policy -> usk
  val encaps : (module RNG) -> mpk -> policy -> key * enc
end

module type Signature = sig
  type sk
  type vk
  type seal

  val gen_sk : (module RNG) -> sk
  val get_vk : sk -> vk
  val sign : sk -> msg:bytes -> seal
  val verify : vk -> msg:bytes -> seal -> bool
end
