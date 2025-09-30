module RNG = Mirage_crypto_rng.Fortuna
module Resolver = Resolver

let _2s = 2_000_000_000
let ( let@ ) finally fn = Fun.protect ~finally fn
let rec forever () = Mkernel.sleep _2s; forever ()

let run _ cidr gateway features =
  let devices =
    let open Mkernel in
    [ Mnet.stackv4 ~name:"service" ?gateway cidr ]
  in
  Mkernel.run devices @@ fun (daemon, tcpv4, udpv4) () ->
  let rng = Mirage_crypto_rng_mkernel.initialize (module RNG) in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill daemon in
  let rng = Mirage_crypto_rng.generate in
  let primary = Dns_server.Primary.create ~rng Dns_resolver_root.reserved in
  let authenticator = Ca_certs_nss.authenticator () in
  let authenticator = Result.get_ok authenticator in
  let tls = Tls.Config.client ~authenticator () in
  let tls = Result.get_ok tls in
  let _resolver, daemon = Resolver.create ~features tls tcpv4 udpv4 primary in
  let@ () = fun () -> Resolver.kill daemon in
  forever ()

open Cmdliner

let output_options = "OUTPUT OPTIONS"
let verbosity = Logs_cli.level ~docs:output_options ()
let renderer = Fmt_cli.style_renderer ~docs:output_options ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  Arg.(value & opt bool true & info [ "with-utf-8" ] ~doc)

let t0 = Mkernel.clock_monotonic ()
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
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
      let res =
        List.fold_left
          (fun acc -> function `Re re -> re :: acc | _ -> acc)
          [] res
      in
      Some (Re.alt res)

let setup_sources = Term.(const setup_sources $ sources)

let setup_logs utf_8 style_renderer sources level =
  Option.iter (Fmt.set_style_renderer Fmt.stdout) style_renderer;
  Fmt.set_utf_8 Fmt.stdout utf_8;
  Logs.set_level level;
  Logs.set_reporter (reporter sources Fmt.stdout);
  Option.is_none level

let setup_logs =
  Term.(const setup_logs $ utf_8 $ renderer $ setup_sources $ verbosity)

let ipv4 =
  let doc = "The IP address of the unikernel." in
  let ipaddr = Arg.conv (Ipaddr.V4.Prefix.of_string, Ipaddr.V4.Prefix.pp) in
  let open Arg in
  required & opt (some ipaddr) None & info [ "ipv4" ] ~doc ~docv:"IPv4"

let ipv4_gateway =
  let doc = "The IP gateway." in
  let ipaddr = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  let open Arg in
  value & opt (some ipaddr) None & info [ "ipv4-gateway" ] ~doc ~docv:"IPv4"

let features =
  let open Arg in
  let dnssec = info [ "dnssec" ] ~doc:"DNSSec validation" in
  let opportunistic_tls_authoritative =
    let doc = "Opportunistic encryption using TLS to the authoritative" in
    info [ "opportunistic-tls-authoritative" ] ~doc
  in
  let qname_minimisation =
    let doc = "Query name minimisation" in
    info [ "qname-minimisation" ] ~doc
  in
  let flags =
    [
      (`Dnssec, dnssec)
    ; (`Opportunistic_tls_authoritative, opportunistic_tls_authoritative)
    ; (`Qname_minimisation, qname_minimisation)
    ]
  in
  let defaults = [] in
  value & vflag_all defaults flags

let term =
  let open Term in
  const run $ setup_logs $ ipv4 $ ipv4_gateway $ features

let cmd =
  let info = Cmd.info "pagejaune" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
