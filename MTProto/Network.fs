module Network

open System
open System.Security.Cryptography

// network is a map of message queues
// sender looks up intended receipient and puts message in the queue

type User = string * string * ECDiffieHellmanCng
type Users = Map<string,User>
type MessageQueue = (byte[] * byte[]) list
type Network = Map<string,MessageQueue * ECDiffieHellmanPublicKey>

let join (user:User) (network:Network) : Network =
    let username, password, dh = user
    Map.add username ([],dh.PublicKey) network

//  enqueue (hostname:string) (message:byte[]) (network : n:Network{Map.exists hostname network})
//  ->  ('n:Network{Map.exists hostname network})
let enqueue (hostname:string) (msgKey:byte[]) (message:byte[]) (network:Network) : Network option =
    let queue = Map.tryFind hostname network
    match queue with
    | Some (q, dh) ->
        let newQ = q @ [msgKey,message]
        Some (Map.add hostname (newQ, dh) network)
    | None -> 
        None

//  dequeue (hostname:string) (network : n:Network{Map.exists hostname network}) -> byte[] * Network
let dequeue (hostname:string) (network:Network) =
    let queue = Map.tryFind hostname network
    match queue with
    | Some (q, dh) ->
        match q with
        | [] -> None, network
        | [x] ->
            let newNet = Map.add hostname ([], dh) network
            Some x, newNet
        | x::xs ->
            let newNet = Map.add hostname (xs, dh) network
            Some x, newNet
    | None -> 
        Console.WriteLine("Host not found")
        None, network