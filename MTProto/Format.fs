module Format

open System.Text

type Column = byte * byte * byte * byte
type Block = Column * Column * Column * Column
let enc = new ASCIIEncoding()

let columnMap fn column =
    let (e0, e1, e2, e3) = column
    (fn e0, fn e1, fn e2, fn e3)

let blockMap fn block =
    let (e0, e1, e2, e3) = block
    (columnMap fn e0, columnMap fn e1, columnMap fn e2, columnMap fn e3) 

let bytesToColumn(bytes:byte[]) : Column  = 
    //if Array.length bytes = 4
    (bytes.[0],bytes.[1],bytes.[2],bytes.[3])

let bytesToBlock (bytes:byte[]) : Block option =
//  bytesToBlock (bytes : ba:byte[]{Array.length ba = 16}) : Block
    if Array.length bytes = 16
    then Some
           ((bytes.[0],bytes.[1],bytes.[2],bytes.[3]),
            (bytes.[4],bytes.[5],bytes.[6],bytes.[7]),
            (bytes.[8],bytes.[9],bytes.[10],bytes.[11]),
            (bytes.[12],bytes.[13],bytes.[14],bytes.[15]))
    else None

let bytesToBlockList (bytes:byte[]) : Block list option =
//  bytesToBlockList (bytes : bas:byte[]{(Array.length bas) % 16 = 0}) : Block list
    if Array.length bytes % 16 = 0
    then Array.map (fun b -> (bytesToBlock b).Value) (Array.chunkBySize 16 bytes) |> Array.toList |> Some
    else None

let partitionString (message:string) : (Block list) option =
//  partitionString (message : s:string{String.length s > 0}) -> (Block list) 
    let rec padSize num acc =
        if num > acc then padSize num (acc+16) else acc
    // find the message size including padding
    let s = message.PadRight (padSize (String.length message) 0)
    let arr = Array.chunkBySize 16 (enc.GetBytes(s))
    Array.fold
        (fun list elem -> 
            match bytesToBlock elem, list with
            | Some block, Some list -> Some (list @ [block]) 
            | _, _ -> None
            )
        (Some [])
        arr

let stringToKey (message:string) : Block option =
    if String.length message > 0
    then Some ( List.head <| (partitionString message).Value )
    else None 


let xorColumns (col1:Column) (col2:Column) : Column =
    let (ca0, ca1, ca2, ca3) = col1
    let (cb0, cb1, cb2, cb3) = col2
    (ca0 ^^^ cb0, ca1 ^^^ cb1, ca2 ^^^ cb2, ca3 ^^^ cb3)

let xorBlocks (block1:Block) (block2:Block) : Block =        
    let (ba0, ba1, ba2, ba3) = block1
    let (bb0, bb1, bb2, bb3) = block2
    (xorColumns ba0 bb0, xorColumns ba1 bb1, xorColumns ba2 bb2, xorColumns ba3 bb3)

let unpackBlock (block:Block) : byte[] =        
    let ((ea0, ea1, ea2, ea3),
         (ea4, ea5, ea6, ea7),
         (ea8, ea9, ea10, ea11),
         (ea12, ea13, ea14, ea15)) = block
    [|  ea0;ea1;ea2;ea3;
        ea4;ea5;ea6;ea7;
        ea8;ea9;ea10;ea11;
        ea12;ea13;ea14;ea15|]


let blockToString (block:Block) : string =    
    enc.GetString <| unpackBlock block