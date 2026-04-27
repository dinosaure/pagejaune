module RNG = Mirage_crypto_rng.Fortuna

let _2s = 2_000_000_000
let ( let@ ) finally fn = Fun.protect ~finally fn
let rec forever () = Mkernel.sleep _2s; forever ()
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

module Stub = Stub

let run _ (cidr, gateway, ipv6) nameservers happy_eyeballs =
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidr ])
  @@ fun rng (daemon, tcp, udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill daemon in
  let hed, he = Mnet_happy_eyeballs.create ~happy_eyeballs tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let cfg = Stub.config ~nameservers 53 in
  let _stub, _daemon = Stub.create cfg tcp udp (udp, he) in
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

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ Mnet_cli.setup_nameservers ()
  $ setup_happy_eyeballs

let cmd =
  let info = Cmd.info "pagejaune" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
