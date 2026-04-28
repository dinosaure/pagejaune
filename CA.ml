let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

let prefix =
  X509.Distinguished_name.
    [ Relative_distinguished_name.singleton (CN "Annuaire") ]

let cacert_dn =
  let open X509.Distinguished_name in
  prefix @ [ Relative_distinguished_name.singleton (CN "Annuaire") ]

let _365d = Ptime.Span.v (365, 0L)
let _30d = Ptime.Span.v (30, 0L)
let _10s = Ptime.Span.of_int_s 10
let ( let* ) = Result.bind

let make domain_name ~seed ?(lifetime = _365d) () =
  let* domain_name = Domain_name.of_string domain_name in
  let* domain_name = Domain_name.host domain_name in
  let pk =
    let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
    let priv, _ = Mirage_crypto_ec.P256.Dsa.generate ~g () in
    `P256 priv
  in
  let now = Mirage_ptime.now () in
  let valid_from = Option.get Ptime.(sub_span now _10s) in
  let* valid_until =
    Ptime.add_span valid_from lifetime
    |> Option.to_result ~none:(msgf "End time out of range")
  in
  let* ca_csr = X509.Signing_request.create cacert_dn pk in
  let extensions =
    let open X509 in
    let open X509.Extension in
    let key_id = Public_key.id Signing_request.((info ca_csr).public_key) in
    let domain_name = Domain_name.to_string domain_name in
    empty
    |> add Subject_alt_name (true, General_name.(singleton DNS [ domain_name ]))
    |> add Basic_constraints (true, (false, None))
    |> add Key_usage (true, [ `Digital_signature ])
    |> add Ext_key_usage (true, [ `Server_auth ])
    |> add Subject_key_id (false, key_id)
  in
  let* cert =
    X509.Signing_request.sign ~valid_from ~valid_until ~extensions ca_csr pk
      cacert_dn
    |> Result.map_error (msgf "%a" X509.Validation.pp_signature_error)
  in
  Ok (cert, pk, valid_until)

let tlsa_of_cert cert =
  let pk = X509.Certificate.public_key cert in
  let data = X509.Public_key.fingerprint ~hash:`SHA256 pk in
  {
    Dns.Tlsa.cert_usage= Dns.Tlsa.Domain_issued_certificate
  ; selector= Dns.Tlsa.Subject_public_key_info
  ; matching_type= Dns.Tlsa.SHA256
  ; data
  }

type cfg = {
    domain: [ `host ] Domain_name.t
  ; ipaddr: Ipaddr.V4.t
  ; lifetime: Ptime.Span.t
  ; renew_before: Ptime.Span.t
  ; ttl: int32
}

let cfg ?(lifetime = _365d) ?(renew_before = _30d) ?(ttl = 3600l) ipaddr domain
    =
  { domain; ipaddr; lifetime; renew_before; ttl }

let make_tls_config cert pk =
  let chain = ([ cert ], pk) in
  Tls.Config.server ~certificates:(`Single chain) ()

let generate tls =
  let ( let* ) = Result.bind in
  let seed = Mirage_crypto_rng.generate 32 in
  let lifetime = tls.lifetime in
  let domain = Domain_name.to_string tls.domain in
  let* cert, pk, valid_until = make domain ~seed ~lifetime () in
  let tlsa = tlsa_of_cert cert in
  let* cfg = make_tls_config cert pk in
  Ok (cfg, tlsa, valid_until)

let zone tls =
  let domain = Domain_name.raw tls.domain in
  let soa = Dns.Soa.create domain in
  let ns = Domain_name.Host_set.singleton tls.domain in
  let a = Ipaddr.V4.Set.singleton tls.ipaddr in
  let map =
    Dns.Rr_map.empty
    |> Dns.Rr_map.add Dns.Rr_map.Soa soa
    |> Dns.Rr_map.add Dns.Rr_map.Ns (tls.ttl, ns)
    |> Dns.Rr_map.add Dns.Rr_map.A (tls.ttl, a)
  in
  Domain_name.Map.singleton domain map

let tlsa_name ?(port = 853) tls =
  let raw = Domain_name.raw tls.domain in
  let n = Domain_name.prepend_label_exn raw "_tcp" in
  Domain_name.prepend_label_exn n (Fmt.str "_%d" port)

let with_tlsa ?(port = 853) tls tlsa trie =
  let name = tlsa_name ~port tls in
  let v =
    List.fold_left
      (Fun.flip Dns.Rr_map.Tlsa_set.add)
      Dns.Rr_map.Tlsa_set.empty tlsa
  in
  Dns_trie.replace name Dns.Rr_map.Tlsa (tls.ttl, v) trie

let zone ?(port = 853) tls ~tlsa trie =
  Dns_trie.insert_map (zone tls) trie |> with_tlsa ~port tls [ tlsa ]
