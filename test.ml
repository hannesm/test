

(* let cert = "aaa" *)
let cert = ""

let str_to_cs buf =
  let pg = Io_page.to_cstruct (Io_page.get 1) in
  let len = String.length buf in
  Cstruct.blit_from_string buf 0 pg 0 len;
  Cstruct.sub pg 0 len

let () =
  let cs1 = Cstruct.of_string cert
  and cs2 = str_to_cs cert
  in
  assert (Cstruct.len cs1 = Cstruct.len cs2) ;
  for i = 0 to pred (Cstruct.len cs1) do
    assert (Cstruct.get_uint8 cs1 i = Cstruct.get_uint8 cs2 i) ;
  done;
  assert (Cstruct.to_bigarray cs1 = Cstruct.to_bigarray cs2)
