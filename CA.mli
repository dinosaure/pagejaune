type cfg = {
    domain: [ `host ] Domain_name.t
  ; ipaddr: Ipaddr.V4.t
  ; lifetime: Ptime.Span.t
  ; renew_before: Ptime.Span.t
  ; ttl: int32
}

val cfg :
     ?lifetime:Ptime.span
  -> ?renew_before:Ptime.span
  -> ?ttl:int32
  -> Ipaddr.V4.t
  -> [ `host ] Domain_name.t
  -> cfg

val generate :
  cfg -> (Tls.Config.server * Dns.Tlsa.t * Ptime.t, [> `Msg of string ]) result

val with_tlsa : ?port:int -> cfg -> Dns.Tlsa.t list -> Dns_trie.t -> Dns_trie.t
val zone : ?port:int -> cfg -> tlsa:Dns.Tlsa.t -> Dns_trie.t -> Dns_trie.t
