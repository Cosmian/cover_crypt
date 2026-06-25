open Core

module type RNG = sig
  type t

  val init : unit -> t
  val fill : t -> bytes -> unit
  val draw : t -> int -> bytes
end

module type Signature = sig
  type sk
  type vk
  type signature

  val keygen : (module RNG) -> sk * vk
  val derive : sk -> vk
  val sign : sk -> msg:string -> signature
  val verf : vk -> msg:string -> signature -> bool
end

module type MAC = sig
  type key
  type tag

  val keygen : (module RNG) -> key
  val mac : key -> msg:string -> tag
end

module type Group = sig
  type t

  val id : t
  val op : t -> t -> t
  val inv : t -> t
end

module type AbelianGroup = sig
  include Group

  val zero : t
  val ( + ) : t -> t -> t
  val ( - ) : t -> t -> t
end

module type Ring = sig
  include AbelianGroup

  val one : t
  val ( * ) : t -> t -> t
  val ( / ) : t -> t -> t option
end

module type KH_NIKE = sig
  module Sk : sig
    include Ring
    include Serializable with type t := t
  end

  module Pk : sig
    include Group
    include Serializable with type t := t
  end

  type key

  val op : Pk.t -> Sk.t -> Pk.t
  val keygen : (module RNG) -> Sk.t * Pk.t
  val session : Pk.t -> Sk.t -> key
end

module type KEM = sig
  type dk
  type ek
  type enc

  val keygen : (module RNG) -> dk * ek
  val encaps : (module RNG) -> ek -> bytes * enc
  val decaps : dk -> enc -> bytes
end
