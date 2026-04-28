let src = Logs.Src.create "pageblanche.stub"

module Log = (val Logs.src_log src : Logs.LOG)

let _2s = 2_000_000_000

type io_addr =
  [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]

type cfg = {
    cache_size: int option
  ; edns: [ `Auto | `Manual of Dns.Edns.t | `None ] option
  ; nameservers: (Dns.proto * io_addr list) option
  ; timeout: int64 option
  ; port: int
  ; secure_port: int
}

let config ?cache_size ?edns ?nameservers ?timeout ?(secure_port = 853) port =
  { cache_size; edns; nameservers; timeout; port; secure_port }

exception Timeout

let with_timeout ~timeout fn =
  let prm0 = Miou.async @@ fun () -> Mkernel.sleep timeout; raise Timeout in
  let prm1 = Miou.async fn in
  match Miou.await_first [ prm0; prm1 ] with
  | Error Timeout -> Error `Timeout
  | Ok v -> Ok v
  | Error exn -> Error (`Exn exn)

let rec clean_up orphans =
  match Miou.care orphans with
  | Some None | None -> ()
  | Some (Some prm) ->
      begin match Miou.await prm with
      | Ok () -> clean_up orphans
      | Error exn ->
          Log.debug (fun m ->
              m "per-connection task ended with %s" (Printexc.to_string exn));
          clean_up orphans
      end

type t = {
    mutex: Miou.Mutex.t
  ; mutable server: Dns_server.t
  ; client: Mnet_dns.t
  ; ban: Ban.t
}

let with_tcp t ~handler tcp port =
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ =
      Miou.async ~orphans @@ fun () ->
      let _, (dst, _) = Mnet.TCP.peers flow in
      let finally = Mnet.TCP.close in
      let res = Miou.Ownership.create ~finally flow in
      Miou.Ownership.own res;
      let rec go () =
        let len = Bytes.create 2 in
        Mnet.TCP.really_read flow len;
        let len = Bytes.get_uint16_be len 0 in
        let buf = Bytes.create len in
        Mnet.TCP.really_read flow buf;
        match handler t `Tcp dst (Bytes.unsafe_to_string buf) with
        | None -> go ()
        | Some (_ttl, str) ->
            let len = Bytes.create 2 in
            Bytes.set_uint16_be len 0 (String.length str);
            let len = Bytes.unsafe_to_string len in
            Mnet.TCP.write flow len; Mnet.TCP.write flow str; go ()
      in
      go ()
    in
    go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp port)

let with_udp t ~handler udp port =
  let rec go () =
    let buf = Bytes.create 4096 in
    let len, (peer, pport) = Mnet.UDP.recvfrom udp ~port buf in
    let str = Bytes.sub_string buf 0 len in
    match handler t `Udp peer str with
    | None -> go ()
    | Some (_ttl, str) ->
        let on_error err =
          Log.warn (fun m ->
              m "Failure while sending to %a:%d: %a" Ipaddr.pp peer pport
                Mnet.UDP.pp_error err)
        in
        let result =
          Mnet.UDP.sendto udp ~dst:peer ~src_port:port ~port:pport str
        in
        Result.iter_error on_error result;
        go ()
  in
  go ()

let with_tls t state ~handler tcp port =
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ =
      Miou.async ~orphans @@ fun () ->
      let _, (dst, dport) = Mnet.TCP.peers flow in
      let finally = Mnet.TCP.close in
      let res0 = Miou.Ownership.create ~finally flow in
      Miou.Ownership.own res0;
      let cfg = Atomic.get state in
      let fn () = Mnet_tls.server_of_fd cfg flow in
      match with_timeout ~timeout:_2s fn with
      | Error (`Timeout | `Exn _) ->
          Log.warn (fun m ->
              m "TLS handshake failed with %a:%d" Ipaddr.pp dst dport);
          Miou.Ownership.release res0
      | Ok tls ->
          let finally = Mnet_tls.close in
          let res1 = Miou.Ownership.create ~finally tls in
          Miou.Ownership.disown res0;
          Miou.Ownership.own res1;
          let rec go () =
            let len = Bytes.create 2 in
            Mnet_tls.really_read tls len;
            let len = Bytes.get_uint16_be len 0 in
            let buf = Bytes.create len in
            Mnet_tls.really_read tls buf;
            match handler t `Tcp dst (Bytes.unsafe_to_string buf) with
            | None -> go ()
            | Some (_ttl, str) ->
                let len = Bytes.create 2 in
                Bytes.set_uint16_be len 0 (String.length str);
                let len = Bytes.unsafe_to_string len in
                Mnet_tls.write tls len; Mnet_tls.write tls str; go ()
          in
          go ()
    in
    go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp port)

let reply hdr question proto ?additional data =
  let ttl = Dns.Packet.minimum_ttl data in
  let pkt = Dns.Packet.create ?additional hdr question data in
  (ttl, fst (Dns.Packet.encode proto pkt))

let query trie question data hdr proto =
  match Dns_server.handle_question trie question with
  | Error (Dns.Rcode.NotAuth, _) -> None
  | Error (rcode, answer) ->
      let opcode = Dns.Packet.opcode_data data in
      let data = `Rcode_error (rcode, opcode, answer) in
      let reply = reply hdr question proto data in
      Some (reply, rcode)
  | Ok (_flags (* TODO *), answer, additional) ->
      let data = `Answer answer in
      let ttl = Dns.Packet.minimum_ttl data in
      let pkt = Dns.Packet.create ?additional hdr question data in
      let pkt =
        match Dns_block.edns pkt with
        | None -> pkt
        | Some edns -> Dns.Packet.with_edns pkt (Some edns)
      in
      let reply = (ttl, fst (Dns.Packet.encode proto pkt)) in
      Some (reply, Dns.Packet.rcode_data data)

let tsig_decode_sign server proto pkt str hdr question =
  let now = Mirage_ptime.now () in
  match Dns_server.handle_tsig server now pkt str with
  | Error _ ->
      let opcode = Dns.Packet.opcode_data pkt.Dns.Packet.data in
      let data = `Rcode_error (Dns.Rcode.Refused, opcode, None) in
      let reply = reply hdr question proto data in
      Error (reply, Dns.Rcode.Refused)
  | Ok key ->
      let sign data =
        let ttl = Dns.Packet.minimum_ttl data in
        let pkt = Dns.Packet.create hdr question data in
        match key with
        | None ->
            let rcode = Dns.Packet.rcode_data data in
            Some ((ttl, fst (Dns.Packet.encode proto pkt)), rcode)
        | Some (name, _tsig, mac, key) ->
            let result =
              Dns_tsig.encode_and_sign ~proto ~mac pkt now key name
            in
            let fn (str, _) = ((ttl, str), Dns.Packet.rcode_data data) in
            let result = Result.map fn result in
            let on_error err =
              Log.err (fun m ->
                  m "Error %a while signing answer" Dns_tsig.pp_s err)
            in
            Result.iter_error on_error result;
            Result.to_option result
      in
      let fn (name, _, _, _) = name in
      let key = Option.map fn key in
      Ok (key, sign)

let axfr server proto pkt question str hdr =
  match tsig_decode_sign server proto pkt str hdr question with
  | Error err -> Some err
  | Ok (key, sign) ->
      begin match Dns_server.handle_axfr_request server proto key question with
      | Error rcode ->
          let opcode = Dns.Packet.opcode_data pkt.Dns.Packet.data in
          let err = `Rcode_error (rcode, opcode, None) in
          let reply = reply hdr question proto err in
          Some (reply, rcode)
      | Ok axfr -> sign (`Axfr_reply axfr)
      end

let update t proto _ipaddr pkt question u str hdr =
  Miou.Mutex.protect t.mutex @@ fun () ->
  let server = t.server in
  match tsig_decode_sign server proto pkt str hdr question with
  | Error err -> Some err
  | Ok (key, sign) ->
      begin match Dns_server.handle_update server proto key question u with
      | Ok (trie, _) ->
          let server = Dns_server.with_data server trie in
          t.server <- server;
          sign `Update_ack
      | Error rcode ->
          let err = `Rcode_error (rcode, Dns.Opcode.Update, None) in
          sign err
      end

let server t proto ipaddr pkt hdr question data str =
  match data with
  | `Query -> query t.server question data hdr proto
  | `Axfr_request -> axfr t.server proto pkt question str hdr
  | `Update u -> update t proto ipaddr pkt question u str hdr
  | _ ->
      let opcode = Dns.Packet.opcode_data pkt.Dns.Packet.data in
      let data = `Rcode_error (Dns.Rcode.NotImp, opcode, None) in
      let pkt = reply hdr question proto data in
      Some (pkt, Dns.Rcode.NotImp)

let resolve t question data hdr proto =
  let name = fst question in
  match (data, snd question) with
  | `Query, `K (Dns.Rr_map.K key) ->
      begin match Mnet_dns.get_resource_record t.client key name with
      | Error (`Msg msg) ->
          Log.err (fun m -> m "Couldn't resolve %s" msg);
          let data = `Rcode_error Dns.(Rcode.ServFail, Opcode.Query, None) in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.ServFail)
      | Error (`No_data (domain, soa)) ->
          let answer =
            let open Dns.Name_rr_map in
            (empty, singleton domain Soa soa)
          in
          let data = `Answer answer in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.NoError)
      | Error (`No_domain (domain, soa)) ->
          let answer =
            let open Dns.Name_rr_map in
            (empty, singleton domain Soa soa)
          in
          let rcode = Dns.Rcode.NXDomain in
          let data = `Rcode_error (rcode, Dns.Opcode.Query, Some answer) in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.NXDomain)
      | Ok value ->
          let answer =
            let open Dns.Name_rr_map in
            (singleton name key value, empty)
          in
          let data = `Answer answer in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.NoError)
      end
  | _ ->
      Log.err (fun m ->
          m "Not implemented %a, data %a" Dns.Packet.Question.pp question
            Dns.Packet.pp_data data);
      let opcode = Dns.Packet.opcode_data data in
      let data = `Rcode_error (Dns.Rcode.NotImp, opcode, None) in
      let reply = reply hdr question proto data in
      Some (reply, Dns.Rcode.NotImp)

let blocked_reply hdr question proto =
  let name = fst question in
  let soa = Dns.Soa.create name in
  let answer =
    let open Dns.Name_rr_map in
    (empty, singleton name Soa soa)
  in
  let data = `Rcode_error (Dns.Rcode.NXDomain, Dns.Opcode.Query, Some answer) in
  reply hdr question proto data

let handler t proto ipaddr str =
  match Dns.Packet.decode str with
  | Error err ->
      Log.err (fun m -> m "Couldn't decode %a" Dns.Packet.pp_err err);
      let answer = Dns.Packet.raw_error str Dns.Rcode.FormErr in
      Option.map (fun r -> (0l, r)) answer
  | Ok pkt ->
      let hdr = pkt.Dns.Packet.header
      and question = pkt.Dns.Packet.question
      and data = pkt.Dns.Packet.data in
      let name = fst question in
      let reply =
        match data with
        | `Query when Ban.is_blocked t.ban name ->
            Log.info (fun m -> m "Blocked %a" Domain_name.pp name);
            Some (blocked_reply hdr question proto, Dns.Rcode.NXDomain)
        | _ -> (
            match server t proto ipaddr pkt hdr question data str with
            | Some _ as value -> value
            | None -> resolve t question data hdr proto)
      in
      Option.map fst reply

let span_to_ns span =
  let d, ps = Ptime.Span.to_d_ps span in
  let ns_per_d = 86_400 * 1_000_000_000 in
  (d * ns_per_d) + Int64.to_int (Int64.div ps 1_000L)

let renewal_delay tls ~valid_until =
  let now = Mirage_ptime.now () in
  let target =
    match Ptime.sub_span valid_until tls.CA.renew_before with
    | Some t -> t
    | None -> valid_until
  in
  let span = Ptime.diff target now in
  if Ptime.Span.compare span Ptime.Span.zero <= 0 then 0 else span_to_ns span

let publish_tlsa t cfg tls tlsa =
  Miou.Mutex.protect t.mutex @@ fun () ->
  let trie = t.server.Dns_server.data in
  let trie = CA.with_tlsa ~port:cfg.secure_port tls tlsa trie in
  t.server <- Dns_server.with_data t.server trie

let renew t state cfg tls initial_tlsa initial_valid_until =
  let current_tlsa = ref initial_tlsa in
  let valid_until = ref initial_valid_until in
  let ttl_ns =
    Int64.to_int (Int64.mul (Int64.of_int32 tls.CA.ttl) 1_000_000_000L)
  in
  let rec go () =
    let delay = renewal_delay tls ~valid_until:!valid_until in
    if delay > 0 then Mkernel.sleep delay;
    Log.info (fun m ->
        m "renewing TLS certificate for %a" Domain_name.pp tls.domain);
    match CA.generate tls with
    | Error (`Msg msg) ->
        Log.err (fun m -> m "Renewal failed (%s); retrying in 1h" msg);
        Mkernel.sleep (3_600 * 1_000_000_000);
        go ()
    | Ok (server, tlsa', valid_until') ->
        publish_tlsa t cfg tls [ !current_tlsa; tlsa' ];
        Log.debug (fun m ->
            m "published overlap TLSA set, waiting %lds for caches" tls.ttl);
        if ttl_ns > 0 then Mkernel.sleep ttl_ns;
        Atomic.set state server;
        publish_tlsa t cfg tls [ tlsa' ];
        current_tlsa := tlsa';
        valid_until := valid_until';
        Log.info (fun m ->
            m "TLS certificate renewed (valid until %a)" (Ptime.pp_human ())
              valid_until');
        go ()
  in
  go ()

type daemon = {
    tcp_server: unit Miou.t
  ; udp_server: unit Miou.t
  ; tls_server: unit Miou.t option
  ; crt_update: unit Miou.t option
}

let create cfg ?(with_reserved = true) ?(ban = Ban.empty) ?tls tcp udp client =
  let rng = Mirage_crypto_rng.generate in
  let primary = Dns_server.Primary.create ~rng Dns_trie.empty in
  let primary =
    if with_reserved then
      let trie = Dns_server.Primary.data primary in
      let trie = Dns_trie.insert_map Dns_resolver_root.reserved_zones trie in
      let now = Mirage_ptime.now () in
      let mon = Int64.of_int (Mkernel.clock_monotonic ()) in
      let primary, _ = Dns_server.Primary.with_data primary now mon trie in
      primary
    else primary
  in
  let tls =
    match tls with
    | None -> None
    | Some tls ->
        begin match CA.generate tls with
        | Error (`Msg msg) ->
            Log.err (fun m -> m "Cannot generate initial certificate: %s" msg);
            None
        | Ok (server, tlsa, valid_until) ->
            Log.debug (fun m -> m "Prepare a DNS-over-TLS server");
            let trie = Dns_server.Primary.data primary in
            let trie = CA.zone ~port:cfg.secure_port tls ~tlsa trie in
            Log.debug (fun m -> m "@[<hov>%a@]" Dns_trie.pp trie);
            let now = Mirage_ptime.now () in
            let mon = Int64.of_int (Mkernel.clock_monotonic ()) in
            let primary, _ =
              Dns_server.Primary.with_data primary now mon trie
            in
            Some (primary, server, tls, tlsa, valid_until)
        end
  in
  let primary = match tls with Some (p, _, _, _, _) -> p | None -> primary in
  let server = Dns_server.Primary.server primary in
  let mutex = Miou.Mutex.create () in
  let t = { server; client; mutex; ban } in
  if Ban.cardinal ban > 0 then
    Log.info (fun m -> m "Loaded %d ban entries" (Ban.cardinal ban));
  let tcp_server = Miou.async @@ fun () -> with_tcp t ~handler tcp cfg.port in
  let udp_server = Miou.async @@ fun () -> with_udp t ~handler udp cfg.port in
  let tls_server, crt_update =
    match tls with
    | None -> (None, None)
    | Some (_, server, tls, tlsa, valid_until) ->
        let current = Atomic.make server in
        let listener =
          Miou.async @@ fun () ->
          with_tls t current ~handler tcp cfg.secure_port
        in
        let renewer =
          Miou.async @@ fun () -> renew t current cfg tls tlsa valid_until
        in
        (Some listener, Some renewer)
  in
  let daemon = { tcp_server; udp_server; tls_server; crt_update } in
  (t, daemon)

let kill { tcp_server; udp_server; tls_server; crt_update } =
  Miou.cancel tcp_server;
  Miou.cancel udp_server;
  Option.iter Miou.cancel tls_server;
  Option.iter Miou.cancel crt_update
