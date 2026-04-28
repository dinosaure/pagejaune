let src = Logs.Src.create "pageblanche.ban"

module Log = (val Logs.src_log src : Logs.LOG)

type t = Domain_name.Set.t

let empty = Domain_name.Set.empty
let is_ip s = match Ipaddr.of_string s with Ok _ -> true | Error _ -> false

let strip_comment line =
  match String.index_opt line '#' with
  | Some i -> String.sub line 0 i
  | None -> line

let split_ws s =
  String.split_on_char ' ' s
  |> List.concat_map (String.split_on_char '\t')
  |> List.filter (fun w -> w <> "")

let add_token set tok =
  match Domain_name.of_string tok with
  | Error _ -> set
  | Ok name -> Domain_name.Set.add (Domain_name.canonical name) set

let add_line set line =
  let line = strip_comment line in
  let line = String.trim line in
  if line = "" then set
  else if String.length line > 0 && (line.[0] = '!' || line.[0] = ';') then set
  else
    match split_ws line with
    | [] -> set
    | first :: rest ->
        let tokens = if is_ip first then rest else first :: rest in
        List.fold_left add_token set tokens

let is_blocked set name =
  let name = Domain_name.canonical (Domain_name.raw name) in
  let rec go n =
    if Domain_name.equal n Domain_name.root then false
    else if Domain_name.Set.mem n set then true
    else
      match Domain_name.drop_label n with
      | Ok parent -> go parent
      | Error _ -> false
  in
  go name

let cardinal = Domain_name.Set.cardinal
