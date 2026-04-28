let src = Logs.Src.create "pageblanche.pin"
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Log = (val Logs.src_log src : Logs.LOG)

type t = Dns.Rr_map.Tlsa_set.t Atomic.t

let v initial = Atomic.make initial
let get t = Atomic.get t
let set t v = Atomic.set t v

let pp_tlsa ppf tlsa =
  Fmt.pf ppf "%d %d %d %s"
    (Dns.Tlsa.cert_usage_to_int tlsa.Dns.Tlsa.cert_usage)
    (Dns.Tlsa.selector_to_int tlsa.Dns.Tlsa.selector)
    (Dns.Tlsa.matching_type_to_int tlsa.Dns.Tlsa.matching_type)
    (Ohex.encode tlsa.Dns.Tlsa.data)

let leaf_spki_matches pins leaf =
  let pk = X509.Certificate.public_key leaf in
  let fg = X509.Public_key.fingerprint ~hash:`SHA256 pk in
  Dns.Rr_map.Tlsa_set.exists
    (fun tlsa ->
      tlsa.Dns.Tlsa.cert_usage = Dns.Tlsa.Domain_issued_certificate
      && tlsa.Dns.Tlsa.selector = Dns.Tlsa.Subject_public_key_info
      && tlsa.Dns.Tlsa.matching_type = Dns.Tlsa.SHA256
      && String.equal tlsa.Dns.Tlsa.data fg)
    pins

let authenticator t : X509.Authenticator.t =
 fun ?ip:_ ~host:_ certs ->
  match certs with
  | [] -> error_msgf "Certificate not found"
  | leaf :: _ ->
      let pins = Atomic.get t in
      if leaf_spki_matches pins leaf then begin
        Log.debug (fun m ->
            m "Upstream certificate matches one of %d pinned TLSA(s)"
              (Dns.Rr_map.Tlsa_set.cardinal pins));
        Ok None
      end
      else begin
        let pk = X509.Certificate.public_key leaf in
        let fg = X509.Public_key.fingerprint ~hash:`SHA256 pk in
        Log.warn (fun m ->
            m "Upstream cert SPKI %s does not match any of %d pinned TLSA(s)"
              (Ohex.encode fg)
              (Dns.Rr_map.Tlsa_set.cardinal pins));
        error_msgf "Invalid chain"
      end
