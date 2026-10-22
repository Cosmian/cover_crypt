open Core

module type S = sig
  type keylen

  val keylen : keylen Nat.t

  module Nike : NIKE with type keylen = keylen
  module Kem : KEM with type k = keylen
  module Signature : Signature

  module G : sig
    val hash : keylen sbytes -> Nike.sk
  end

  module T : sig
    type t

    val hash : Kem.enc list -> t
  end

  module H : sig
    type t = private keylen sbytes

    val hash : Nike.key -> Kem.key -> c1:Nike.pk -> c2:Nike.pk -> T.t -> t
  end

  module Otp : OTP with type keylen = keylen and type key = H.t

  module U : sig
    type t

    val hash : Otp.ctx list -> t:T.t -> t
  end

  module J : sig
    type key = keylen sbytes
    type tag = keylen sbytes

    val hash :
      secret:keylen sbytes -> c1:Nike.pk -> c2:Nike.pk -> U.t -> key * tag
  end
end

module Make
    (Hash : Hash)
    (Sign : Signature)
    (Kem : KEM)
    (Nike : NIKE with type keylen = Kem.k) =
struct
  module Kem = Kem
  module Nike = Nike
  module Signature = Sign
end
