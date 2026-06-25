module type Serializable = sig
  type t

  val to_string : t -> string
  val to_bytes : t -> bytes
end

let xor_in_place ~dest other =
  if Bytes.length dest <> Bytes.length other then
    invalid_arg "cannot XOR numbers of bytes"
  else
    for pos = 0 to Bytes.length dest - 1 do
      let b1 = Bytes.unsafe_get dest pos |> Char.code in
      let b2 = Bytes.unsafe_get other pos |> Char.code in
      Bytes.unsafe_set dest pos (Int.logxor b1 b2 |> Char.chr)
    done
