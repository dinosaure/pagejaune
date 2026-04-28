type t

val empty : t
val cardinal : t -> int
val add_line : t -> string -> t
val is_blocked : t -> 'a Domain_name.t -> bool
