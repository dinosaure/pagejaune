(** Live, mutable set of TLSA records used by an [X509.Authenticator.t] to
    validate an upstream DoT server. The authenticator built once with
    {!authenticator} closes over the underlying state, so {!set} updates take
    effect on the next TLS handshake without rebuilding any TLS config. *)

type t

val v : Dns.Rr_map.Tlsa_set.t -> t
val get : t -> Dns.Rr_map.Tlsa_set.t
val set : t -> Dns.Rr_map.Tlsa_set.t -> unit

val authenticator : t -> X509.Authenticator.t
(** A dynamic authenticator. Accepts a chain whose leaf certificate's
    SubjectPublicKeyInfo (SHA256) matches any pin currently in [t] advertised as
    DANE-EE [3 1 1]. *)

val pp_tlsa : Dns.Tlsa.t Fmt.t
