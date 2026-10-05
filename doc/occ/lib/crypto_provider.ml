open Core

module type S = sig
  type keylen

  val keylen : keylen Nat.t

  module Nike : NIKE
  module Kem : KEM with type n = keylen
  module Sig : Signature with type n = keylen

  module G : sig
    val hash : keylen sbytes -> Nike.sk
  end

  module T : sig
    type t

    val hash : Kem.enc list -> t
  end

  module U : sig
    type t

    val hash : keylen sbytes list -> t:T.t -> t
  end

  module H : sig
    type hash = keylen sbytes

    val hash : Nike.key -> Kem.key -> c1:Nike.pk -> c2:Nike.pk -> T.t -> hash
  end

  module J : sig
    type key = keylen sbytes
    type tag = keylen sbytes

    val hash :
      secret:keylen sbytes -> c1:Nike.pk -> c2:Nike.pk -> U.t -> key * tag
  end
end
