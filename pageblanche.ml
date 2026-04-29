module RNG = Mirage_crypto_rng.Fortuna

let _2s = 2_000_000_000
let ( let@ ) finally fn = Fun.protect ~finally fn
let rec forever () = Mkernel.sleep _2s; Gc.compact (); forever ()
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]
let ( let* ) = Result.bind
let guard ~err fn = if fn () then Ok () else Error err
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

module Stub = Stub

module Blk = struct
  type t = Mkernel.Block.t

  let pagesize = Mkernel.Block.pagesize
  let read = Mkernel.Block.atomic_read
  let write = Mkernel.Block.atomic_write
end

module Bos = Mfat_bos.Make (Blk)

let fat32 ~name =
  let fn blk () =
    let v = Bos.create blk in
    let v = Result.map_error (fun (`Msg msg) -> msg) v in
    Result.error_to_failure v
  in
  Mkernel.map fn [ Mkernel.block name ]

let banlist fs =
  let is_txt p = Fpath.has_ext ".txt" p in
  let process_file acc path =
    match Bos.File.read_lines fs path with
    | Error (`Msg msg) ->
        Logs.warn (fun m -> m "skip %a: %s" Fpath.pp path msg);
        acc
    | Ok lines ->
        let n0 = Ban.cardinal acc in
        let acc = List.fold_left Ban.add_line acc lines in
        Logs.info (fun m ->
            m "loaded %a (+%d entries)" Fpath.pp path (Ban.cardinal acc - n0));
        acc
  in
  let elements = `Files
  and traverse = `Sat (fun _ _ -> Ok true)
  and fn path acc = if is_txt path then process_file acc path else acc in
  let acc = Bos.fold ~elements ~traverse fs fn Ban.empty [ Fpath.v "lists/" ] in
  match acc with
  | Ok set -> set
  | Error (`Msg msg) ->
      Logs.warn (fun m -> m "Could not enumerate ban lists: %s" msg);
      Ban.empty

let _60s = 60l
let _1d = 86_400l

let refresh client pin tlsa_name =
  let rec go () =
    let pins_before = Pin.get pin in
    Logs.info (fun m -> m "Asking for %a" Domain_name.pp tlsa_name);
    match Mnet_dns.get_resource_record client Dns.Rr_map.Tlsa tlsa_name with
    | Error err ->
        let pp_err ppf = function
          | `Msg msg -> Fmt.string ppf msg
          | `No_data _ -> Fmt.string ppf "no TLSA record"
          | `No_domain _ -> Fmt.string ppf "domain does not exist"
        in
        Logs.warn (fun m ->
            m "upstream TLSA refresh failed (%a); retrying in 1mn" pp_err err);
        Mkernel.sleep (60 * 1_000_000_000);
        (* 60s *)
        go ()
    | Ok (ttl, set) ->
        if not (Dns.Rr_map.Tlsa_set.equal set pins_before) then begin
          Pin.set pin set;
          Logs.info (fun m ->
              m "upstream pin set updated (%d entries)"
                (Dns.Rr_map.Tlsa_set.cardinal set))
        end;
        let next_secs =
          let half = Int32.div ttl 2l in
          if Int32.compare half _60s < 0 then _60s
          else if Int32.compare half _1d > 0 then _1d
          else half
        in
        Logs.debug (fun m ->
            m "wait %a to ask the next TLSA" Duration.pp
              (Duration.of_sec (Int32.to_int next_secs)));
        Mkernel.sleep (Int32.to_int next_secs * 1_000_000_000);
        go ()
  in
  go ()

let tlsa_of_spki_hash data =
  {
    Dns.Tlsa.cert_usage= Dns.Tlsa.Domain_issued_certificate
  ; selector= Dns.Tlsa.Subject_public_key_info
  ; matching_type= Dns.Tlsa.SHA256
  ; data
  }

let ask_tlsa_to_pagejaune udp he ipaddr port peer_name =
  let nameservers = (`Tcp, [ `Plaintext (ipaddr, port) ]) in
  let dns0 = Mnet_dns.create ~nameservers (udp, he) in
  let raw = Domain_name.raw peer_name in
  let n = Domain_name.prepend_label_exn raw "_tcp" in
  let tlsa_name = Domain_name.prepend_label_exn n (Fmt.str "_%d" port) in
  let* _ttl, set =
    Mnet_dns.get_resource_record dns0 Dns.Rr_map.Tlsa tlsa_name
  in
  let pin = Pin.v set in
  let pagejaune =
    let authenticator = Pin.authenticator pin in
    let cfg = Tls.Config.client ~authenticator ~peer_name () in
    let cfg = Result.get_ok cfg in
    `Tls (cfg, ipaddr, port)
  in
  let nameservers = (`Tcp, [ pagejaune ]) in
  Ok (nameservers, pin, tlsa_name)

let process_pagejaune udp he = function
  | `Ready (nameservers, pin, tlsa_name) -> Some (nameservers, pin, tlsa_name)
  | `Ask (ipaddr, port, peer_name) ->
      let result = ask_tlsa_to_pagejaune udp he ipaddr port peer_name in
      Result.to_option result

let devices ?gateway ~ipv6 cidr =
  let open Mkernel in
  [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidr; fat32 ~name:"lst" ]

let run _ (cidr, gateway, ipv6) pagejaune nameservers happy_eyeballs domain
    lifetime =
  Mkernel.run (devices ?gateway ~ipv6 cidr)
  @@ fun rng (daemon, tcp, udp) fs () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill daemon in
  let hed, he = Mnet_happy_eyeballs.create ~happy_eyeballs tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let ban = banlist fs in
  let cfg = Stub.config 53 in
  let tls =
    let ipaddr = Ipaddr.V4.Prefix.address cidr in
    let lifetime = Ptime.Span.of_int_s (Duration.to_sec lifetime) in
    CA.cfg ~lifetime ipaddr domain
  in
  let pagejaune = Option.bind pagejaune (process_pagejaune udp he) in
  let clients, refresher =
    match pagejaune with
    | Some (nameservers, pin, tlsa_name) ->
        let dns =
          let cache_size = cfg.Stub.cache_size
          and edns = cfg.Stub.edns
          and timeout = cfg.Stub.timeout in
          Mnet_dns.create ?cache_size ?edns ?timeout ~nameservers (udp, he)
        in
        let prm = Miou.async @@ fun () -> refresh dns pin tlsa_name in
        (Some [ dns ], Some prm)
    | _ -> (None, None)
  in
  let@ () = fun () -> Option.iter Miou.cancel refresher in
  let _stub, daemon =
    Stub.create cfg ~ban ~tls ?clients tcp udp he nameservers
  in
  let@ () = fun () -> Stub.kill daemon in
  forever ()

open Cmdliner

let output_options = "OUTPUT OPTIONS"
let verbosity = Logs_cli.level ~docs:output_options ()
let renderer = Fmt_cli.style_renderer ~docs:output_options ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  Arg.(value & opt bool true & info [ "with-utf-8" ] ~doc)

let t0 = Mkernel.clock_monotonic ()
let neg fn = fun x -> not (fn x)

let reporter sources ppf =
  let re = Option.map Re.compile sources in
  let print src =
    let some re = (neg List.is_empty) (Re.matches re (Logs.Src.name src)) in
    Option.fold ~none:true ~some re
  in
  let report src level ~over k msgf =
    let k _ = over (); k () in
    let pp header _tags k ppf fmt =
      let t1 = Mkernel.clock_monotonic () in
      let delta = Float.of_int (t1 - t0) in
      let delta = delta /. 1_000_000_000. in
      Fmt.kpf k ppf
        ("[+%a][%a]%a[%a]: " ^^ fmt ^^ "\n%!")
        Fmt.(styled `Blue (fmt "%04.04f"))
        delta
        Fmt.(styled `Cyan int)
        (Stdlib.Domain.self () :> int)
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src)
    in
    match (level, print src) with
    | Logs.Debug, false -> k ()
    | _, true | _ -> msgf @@ fun ?header ?tags fmt -> pp header tags k ppf fmt
  in
  { Logs.report }

let regexp =
  let parser str =
    match Re.Pcre.re str with
    | re -> Ok (str, `Re re)
    | exception _ -> error_msgf "Invalid PCRegexp: %S" str
  in
  let pp ppf (str, _) = Fmt.string ppf str in
  Arg.conv (parser, pp)

let sources =
  let doc = "A regexp (PCRE syntax) to identify which log we print." in
  let open Arg in
  value & opt_all regexp [ ("", `None) ] & info [ "l" ] ~doc ~docv:"REGEXP"

let setup_sources = function
  | [ (_, `None) ] -> None
  | res ->
      let res = List.map snd res in
      let fn acc = function `Re re -> re :: acc | _ -> acc in
      let res = List.fold_left fn [] res in
      Some (Re.alt res)

let setup_sources = Term.(const setup_sources $ sources)

let setup_logs utf_8 style_renderer sources level =
  Option.iter (Fmt.set_style_renderer Fmt.stdout) style_renderer;
  Fmt.set_utf_8 Fmt.stdout utf_8;
  Logs.set_level level;
  Logs.set_reporter (reporter sources Fmt.stdout);
  Option.is_none level

let setup_logs =
  let open Term in
  const setup_logs $ utf_8 $ renderer $ setup_sources $ verbosity

let setup_happy_eyeballs
    {
      Mnet_cli.aaaa_timeout
    ; connect_delay
    ; connect_timeout
    ; resolve_timeout
    ; resolve_retries
    } =
  let now = Mkernel.clock_monotonic () in
  let now = Int64.of_int now in
  Happy_eyeballs.create ~aaaa_timeout ~connect_delay ~connect_timeout
    ~resolve_timeout ~resolve_retries now

let setup_happy_eyeballs =
  let open Term in
  const setup_happy_eyeballs $ Mnet_cli.setup_happy_eyeballs

let domain =
  let local = Domain_name.of_string_exn "local" in
  let is_valid subdomain =
    Domain_name.is_subdomain ~subdomain ~domain:local
    && Domain_name.count_labels subdomain >= 2
  in
  let parser str =
    let* domain_name = Domain_name.of_string str in
    let* domain_name = Domain_name.host domain_name in
    let* () =
      let err =
        msgf "Invalid domain %a: must end with .local (e.g. foo.local)"
          Domain_name.pp domain_name
      in
      guard ~err @@ fun () -> is_valid domain_name
    in
    Ok domain_name
  in
  let pp = Domain_name.pp in
  Arg.conv (parser, pp)

let domain =
  let doc =
    "Domain name advertised by the unikernel for DNS-over-TLS (e.g. \
     foo.local). The certificate's SAN, the A record and the TLSA record at \
     _853._tcp.<domain> all use this name."
  in
  let open Arg in
  required & opt (some domain) None & info [ "domain" ] ~doc ~docv:"DOMAIN"

let duration =
  let parser = Duration.of_string in
  let pp = Duration.pp in
  Arg.conv (parser, pp)

let lifetime =
  let doc = "Validity period of the self-signed TLS certificate." in
  let open Arg in
  value
  & opt duration (Duration.of_day 365)
  & info [ "tls-lifetime" ] ~doc ~docv:"DURATION"

let pagejaune =
  let parse_pin str =
    match Ohex.decode str with
    | exception _ -> error_msgf "Invalid hex pin %S" str
    | data when String.length data = 32 -> Ok (tlsa_of_spki_hash data)
    | _ -> error_msgf "Pin %S is not a 32-byte SHA-256 digest" str
  in
  let parser str =
    match String.split_on_char '!' str with
    | [ endpoint; host ] ->
        let* ipaddr, port = Ipaddr.with_port_of_string ~default:853 endpoint in
        let* dn = Domain_name.of_string host in
        let* dn = Domain_name.host dn in
        Ok (ipaddr, port, dn, None)
    | [ endpoint; host; pin ] ->
        let* ipaddr, port = Ipaddr.with_port_of_string ~default:853 endpoint in
        let* dn = Domain_name.of_string host in
        let* dn = Domain_name.host dn in
        let* tlsa = parse_pin pin in
        Ok (ipaddr, port, dn, Some tlsa)
    | _ ->
        error_msgf "Expected <ip>[:<port>]!<host>!<spki-sha256-hex>, got %S" str
  in
  let pp ppf = function
    | ipaddr, port, host, Some tlsa ->
        Fmt.pf ppf "%a:%d!%a!%s" Ipaddr.pp ipaddr port Domain_name.pp host
          (Ohex.encode tlsa.Dns.Tlsa.data)
    | ipaddr, port, host, None ->
        Fmt.pf ppf "%a:%d!%a" Ipaddr.pp ipaddr port Domain_name.pp host
  in
  Arg.conv (parser, pp)

let pagejaune =
  let doc =
    "Upstream pagejaune endpoint as <ip>[:<port>]!<host>!<spki-sha256-hex>. \
     When set, $(cmd) forwards every recursive query over DoT to this \
     endpoint. The leaf certificate of pagejaune is authenticated against the \
     DANE-EE 3 1 1 pin given here, which is then refreshed periodically by \
     querying _853._tcp.<host> TLSA over the established channel."
  in
  let open Arg in
  value & opt (some pagejaune) None & info [ "pagejaune" ] ~doc ~docv:"ENDPOINT"

let setup_pagejaune = function
  | None -> None
  | Some (ipaddr, port, peer_name, Some initial_pin) ->
      let pin = Pin.v (Dns.Rr_map.Tlsa_set.singleton initial_pin) in
      let pagejaune =
        let authenticator = Pin.authenticator pin in
        let cfg = Tls.Config.client ~authenticator ~peer_name () in
        let cfg = Result.get_ok cfg in
        `Tls (cfg, ipaddr, port)
      in
      let raw = Domain_name.raw peer_name in
      let n = Domain_name.prepend_label_exn raw "_tcp" in
      let tlsa_name = Domain_name.prepend_label_exn n (Fmt.str "_%d" port) in
      Some (`Ready ((`Tcp, [ pagejaune ]), pin, tlsa_name))
  | Some (ipaddr, port, peer_name, None) ->
      Some (`Ask (ipaddr, port, peer_name))

let setup_pagejaune =
  let open Term in
  const setup_pagejaune $ pagejaune

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ setup_pagejaune
  $ Mnet_cli.nameservers ()
  $ setup_happy_eyeballs
  $ domain
  $ lifetime
  $ pagejaune

let cmd =
  let info = Cmd.info "pageblanche" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
