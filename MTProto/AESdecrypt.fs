module AESdecrypt

open System.Text
open Format
open LookupTables

//  getDecryptionKeys (key:Block) (amount:int) -> ks:Block list{List.length ks = amount}
let private getDecryptionKeys (key:Block) (amount:int) =     
    let rec roundConstants (c:Column list) (round:int) : Column list  =
        match round with
        | 1 -> c
        | x -> roundConstants (bytesToColumn (enc.GetBytes(x.ToString().PadRight 4)) :: c) (round-1)
    List.fold
        (fun (keys:Block list) constant ->
            match keys with
            | [] -> failwith "unreachable"
            | x::xs -> (mutateKey x constant) :: keys 
        )
        [key] 
        (roundConstants [] (amount-1))

//  substituteBytesDecrypt (block:Block) 
//  -> out : b:Block{b != block && (Array.sort <| unpackBlock b) = (Array.sort <| unpackBlock block)}
let private substituteBytesDecrypt (block:Block) =
    let sBoxDecrypt (b:byte) =
        (byte) sBoxDec.[(int)  b]
    blockMap sBoxDecrypt block

//  shiftRowsRight (block:Block)
//  -> out : b:Block{(Array.sort <| unpackBlock b) = (Array.sort <| unpackBlock block)}
let private shiftRowsRight (block:Block) : Block =
    let ((e00, e1, e02, e03),
         (e10, e11, e12, e13),
         (e20, e21, e22, e23),
         (e30, e31, e32, e33)) = block
    ((e00,e31,e22,e13),
     (e10,e1,e32,e23),
     (e20,e11,e02,e33),
     (e30,e21,e12,e03) )

let private mixColumnsDecrypt (block:Block) = 
    let ((e00, e01, e02, e03),
         (e04, e05, e06, e07),
         (e08, e09, e10, e11),
         (e12, e13, e14, e15)) = block

    let byte0 = (byte)(mul14.[(int) e00] ^^^ mul11.[(int) e01] ^^^ mul13.[(int) e02] ^^^ mul9.[(int) e03])
    let byte1 = (byte)(mul9.[(int) e00] ^^^ mul14.[(int) e01] ^^^ mul11.[(int) e02] ^^^ mul13.[(int) e03])
    let byte2 = (byte)(mul13.[(int) e00] ^^^ mul9.[(int) e01] ^^^ mul14.[(int) e02] ^^^ mul11.[(int) e03])
    let byte3 = (byte)(mul11.[(int) e00] ^^^ mul13.[(int) e01] ^^^ mul9.[(int) e02] ^^^ mul14.[(int) e03])

    let byte4 = (byte)(mul14.[(int) e04] ^^^ mul11.[(int) e05] ^^^ mul13.[(int) e06] ^^^ mul9.[(int) e07])
    let byte5 = (byte)(mul9.[(int) e04] ^^^ mul14.[(int) e05] ^^^ mul11.[(int) e06] ^^^ mul13.[(int) e07])
    let byte6 = (byte)(mul13.[(int) e04] ^^^ mul9.[(int) e05] ^^^ mul14.[(int) e06] ^^^ mul11.[(int) e07])
    let byte7 = (byte)(mul11.[(int) e04] ^^^ mul13.[(int) e05] ^^^ mul9.[(int) e06] ^^^ mul14.[(int) e07])

    let byte8 = (byte)(mul14.[(int) e08] ^^^ mul11.[(int) e09] ^^^ mul13.[(int) e10] ^^^ mul9.[(int) e11])
    let byte9 = (byte)(mul9.[(int) e08] ^^^ mul14.[(int) e09] ^^^ mul11.[(int) e10] ^^^ mul13.[(int) e11])
    let byte10 = (byte)(mul13.[(int) e08] ^^^ mul9.[(int) e09] ^^^ mul14.[(int) e10] ^^^ mul11.[(int) e11])
    let byte11 = (byte)(mul11.[(int) e08] ^^^ mul13.[(int) e09] ^^^ mul9.[(int) e10] ^^^ mul14.[(int) e11])

    let byte12 = (byte)(mul14.[(int) e12] ^^^ mul11.[(int) e13] ^^^ mul13.[(int) e14] ^^^ mul9.[(int) e15])
    let byte13 = (byte)(mul9.[(int) e12] ^^^ mul14.[(int) e13] ^^^ mul11.[(int) e14] ^^^ mul13.[(int) e15])
    let byte14 = (byte)(mul13.[(int) e12] ^^^ mul9.[(int) e13] ^^^ mul14.[(int) e14] ^^^ mul11.[(int) e15])
    let byte15 = (byte)(mul11.[(int) e12] ^^^ mul13.[(int) e13] ^^^ mul9.[(int) e14] ^^^ mul14.[(int) e15])
    
    (( byte0 , byte1 , byte2 , byte3),
     ( byte4 , byte5 , byte6 , byte7),
     ( byte8 , byte9 , byte10 , byte11),
     ( byte12 , byte13 , byte14 , byte15))
    
//  retractKey (block:Block) (key:Block) -> b:Block{xorBlocks b key = block}
let private retractKey (block:Block) (key:Block) = 
    xorBlocks block key 

let rec private DecryptRounds (bytes:Block) (keys:Block list) =
    let round (b:Block) (key:Block) =
        b |> retractKey <| key |> mixColumnsDecrypt |> shiftRowsRight |> substituteBytesDecrypt
    match keys with
    | [] -> bytes
    | (k :: ks) -> DecryptRounds (round bytes k) ks

//  DecryptBlockAES (bytes:Block) (key:Block) (amount : i:int{i >= 0})
let private DecryptBlockAES (bytes:Block) (key:Block) (amount:int) =
    let keys = getDecryptionKeys key amount
    //  keys : ks:Block list{List.length ks = amount}
    let lastRound = DecryptRounds bytes (List.rev <| List.tail keys) 
    retractKey lastRound (List.head keys)

let private CBC_IGE_decrypt (crypto:Block list) (key:Block) (iv:Block list) (roundsAmount:int) : Block list =
    let iv1, iv2 = 
        match iv with
        | iv1 :: iv2 :: [] -> iv1, iv2
        | _ -> failwith "invalid IV"
    fst <|
    List.fold
        (fun (message, (prevCipher, prevPlain)) cipherBlock ->
            let plain = DecryptBlockAES cipherBlock key roundsAmount
            ((xorBlocks plain prevCipher :: message), (cipherBlock,plain))
        )
        ([],(iv1,iv2))
        crypto
     
let DecryptStringWith (crypto:byte[]) (key:string) (iv:string) (roundsAmount:int) : string option =
    match bytesToBlockList crypto, stringToKey key, partitionString iv with
    | Some cryptoBlocks, Some keyBlock, Some ivBlock -> 
        let out = 
            List.fold
                (fun plaintext block ->
                        (blockToString block) + plaintext)
                ""
                (CBC_IGE_decrypt cryptoBlocks keyBlock ivBlock roundsAmount)
        Some (out.Trim())
    | None,_,_ -> printf ("fail message"); None
    | _,None,_ -> printf ("fail key"); None
    | _,_,None -> printf ("fail iv"); None
 