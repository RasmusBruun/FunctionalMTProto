module AESencrypt

open System.Text
open Format
open LookupTables

//  getEncryptionKeys (key:Block) (amount:int) -> ks:Block list{List.length ks = amount}
let private getEncryptionKeys (key:Block) (amount:int) =
    let rec roundConstants (c:Column list) (round:int) : Column list  =
        match round with
        | 1 -> c
        | x -> roundConstants (bytesToColumn (enc.GetBytes(x.ToString().PadRight 4)) :: c) (round-1)
    List.fold 
        (fun (keys:Block list) constant ->
            match keys with
            | [] -> failwith "unreachable" // could be proven with dependant types
            | x::xs -> (mutateKey x constant) :: keys 
        )
        [key] 
        (roundConstants [] (amount-1))

//  substituteBytesEncrypt (block:Block) 
//  -> out : b:Block{b != block && (Array.sort <| unpackBlock b) = (Array.sort <| unpackBlock block)}
let private substituteBytesEncrypt (block:Block) : Block =
    let sBoxEncrypt (b:byte) =
        (byte) sBoxEnc.[(int) b]
    blockMap sBoxEncrypt block

//  shiftRowsLeft (block:Block)
//  -> out : b:Block{(Array.sort <| unpackBlock b) = (Array.sort <| unpackBlock block)}
let private shiftRowsLeft (block:Block) : Block =
    let ((e00, e01, e02, e03),
         (e10, e11, e12, e13),
         (e20, e21, e22, e23),
         (e30, e31, e32, e33)) = block
    ((e00,e11,e22,e33),
     (e10,e21,e32,e03),
     (e20,e31,e02,e13),
     (e30,e01,e12,e23) )


let private mixColumnsEncrypt (block:Block) : Block =
    let ((e00, e01, e02, e03),
         (e04, e05, e06, e07),
         (e08, e09, e10, e11),
         (e12, e13, e14, e15)) = block

    let byte0 = (byte)(mul2.[(int) e00] ^^^ mul3.[(int) e01] ^^^ (int) e02 ^^^ (int) e03)
    let byte1 = (byte)((int) e00 ^^^ mul2.[(int) e01] ^^^ mul3.[(int) e02] ^^^ (int) e03)
    let byte2 = (byte)((int) e00 ^^^ (int) e01 ^^^ mul2.[(int) e02] ^^^ mul3.[(int) e03])
    let byte3 = (byte)(mul3.[(int) e00] ^^^ (int) e01 ^^^ (int) e02 ^^^ mul2.[(int) e03])

    let byte4 = (byte)(mul2.[(int) e04] ^^^ mul3.[(int) e05] ^^^ (int) e06 ^^^ (int) e07)
    let byte5 = (byte)((int) e04 ^^^ mul2.[(int) e05] ^^^ mul3.[(int) e06] ^^^ (int) e07)
    let byte6 = (byte)((int) e04 ^^^ (int) e05 ^^^ mul2.[(int) e06] ^^^ mul3.[(int) e07])
    let byte7 = (byte)(mul3.[(int) e04] ^^^ (int) e05 ^^^ (int) e06 ^^^ mul2.[(int) e07])

    let byte8 = (byte)(mul2.[(int) e08] ^^^ mul3.[(int) e09] ^^^ (int) e10 ^^^ (int) e11)
    let byte9 = (byte)((int) e08 ^^^ mul2.[(int) e09] ^^^ mul3.[(int) e10] ^^^ (int) e11)
    let byte10 = (byte)((int) e08 ^^^ (int) e09 ^^^ mul2.[(int) e10] ^^^ mul3.[(int) e11])
    let byte11 = (byte)(mul3.[(int) e08] ^^^ (int) e09 ^^^ (int) e10 ^^^ mul2.[(int) e11])

    let byte12 = (byte)(mul2.[(int) e12] ^^^ mul3.[(int) e13] ^^^ (int) e14 ^^^ (int) e15)
    let byte13 = (byte)((int) e12 ^^^ mul2.[(int) e13] ^^^ mul3.[(int) e14] ^^^ (int) e15)
    let byte14 = (byte)((int) e12 ^^^ (int) e13 ^^^ mul2.[(int) e14] ^^^ mul3.[(int) e15])
    let byte15 = (byte)(mul3.[(int) e12] ^^^ (int) e13 ^^^ (int) e14 ^^^ mul2.[(int) e15])
   
    (( byte0 , byte1 , byte2 , byte3),
     ( byte4 , byte5 , byte6 , byte7),
     ( byte8 , byte9 , byte10 , byte11),
     ( byte12 , byte13 , byte14 , byte15))
        
//  addKey (block:Block) (key:Block) -> b:Block{xorBlocks b key = block}
let private addKey (block:Block) (key:Block) = xorBlocks block key

//  encryptRounds (bytes:Block) (keys:Block list)
let rec private encryptRounds (bytes:Block) (keys:Block list) =
    let round (b:Block) (key:Block) =
        b |> substituteBytesEncrypt |> shiftRowsLeft |> mixColumnsEncrypt |> addKey <| key
    match keys with
    | [] -> bytes
    | (k :: ks) -> encryptRounds (round bytes k) ks

let private EncryptBlockAES (bytes:Block) (key:Block) (amount:int) =
    let keys = getEncryptionKeys key amount
    let init = addKey bytes (List.head keys)
    encryptRounds init (List.tail keys)

let private CBC_IGE_encrypt (message:Block list) (key:Block) (iv:Block list) (roundsAmount:int) : Block list =
    let iv1, iv2 = 
        match iv with
        | iv1 :: iv2 :: [] -> iv1, iv2
        | _ -> failwith "invalid IV"
    fst <|
    List.fold
        (fun (crypto, (prevCipher, prevPlain)) plainBlock ->
            let xoredMessage = xorBlocks prevCipher plainBlock
            let cryptoBlock = EncryptBlockAES xoredMessage key roundsAmount
            let xoredCrypto = xorBlocks cryptoBlock prevPlain
            (crypto @ [cryptoBlock], (cryptoBlock, plainBlock)))
        ([],(iv1,iv2))
        message

let EncryptStringWith (message:string) (key:string) (iv:string) (roundsAmount:int) : byte[] option =
    match partitionString message, stringToKey key, partitionString iv with
    | Some messageBlocks, Some keyBlock, Some ivBlock ->
        Some (
          List.fold
            (fun bytes block ->
                Array.append bytes (unpackBlock block))
            [||]
            (CBC_IGE_encrypt messageBlocks keyBlock ivBlock roundsAmount))
    | None,_,_ -> printf ("fail message"); None
    | _,None,_ -> printf ("fail key"); None
    | _,_,None -> printf ("fail iv"); None
    