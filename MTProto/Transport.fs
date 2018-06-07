module Transport

open System
open System.IO
open System.Security.Cryptography
open System.Text
open AESencrypt
open AESdecrypt
open Network
open Format

let iv = "NonRandomInitializationVector"
let iv1 = let a = Aes.Create() in a.GenerateIV(); a.IV
let sha1 = System.Security.Cryptography.SHA1Cng.Create()

//  requestPKey (hostname:string) (network : n:Network{Map.exists hostname network})
//  -> ECDiffiHellmanPublicKey
let requestPKey (hostname:string) (network:Network) =   
    match Map.tryFind hostname network with
    | Some (_,pKey) -> Some pKey
    | None -> None

//  send (message:string) (sender:User) (receiver:string) (network : n:Network{Map.exists receiver network})
//  -> ECDiffiHellmanPublicKey
let send (message:string) (sender:User) (receiver:string) (network:Network) =
    let _,_,senderDH = sender
    let pkB = requestPKey receiver network
    match pkB with
    | Some pkB ->
        let msgKey = sha1.ComputeHash(enc.GetBytes(message))
        senderDH.Seed <- msgKey
        let privK_ab = senderDH.DeriveKeyMaterial(pkB)
        match EncryptStringWith message (enc.GetString privK_ab) iv 14 with
        | Some crypto -> 
          match enqueue receiver msgKey crypto network with
          | Some res -> ("enqueue success",res)
          | None -> "enqueue fail", network
        | None -> "encryption fail", network   
    | None -> "host not found", network 

//  receive (receiver:User) (author:string) (network : n:Network{Map.exists author network})
//  -> string * Network
let receive (receiver:User) (author:string) (network:Network) =
    let username,password,receiverDH = receiver
    let message,newNetwork = dequeue username network
    match message with
        | Some (msgKey,msg) ->
            let pkB = requestPKey author network
            match pkB with
            | Some pkB ->
                let privK_ab = receiverDH.DeriveKeyMaterial(pkB)
                match DecryptStringWith msg (enc.GetString privK_ab) iv 14 with
                | Some plain ->
                    if sha1.ComputeHash (enc.GetBytes(plain)) = msgKey
                    then Some plain, newNetwork
                    else None, network
                | None -> None, network 
            | None -> None, network
        | None -> None, network
    