module CLI

open System
open System.IO
open System.Security.Cryptography
open AESencrypt
open AESdecrypt
open Network
open Transport
open Test

let program argv =
  Console.WriteLine("Welcome :)");
  // create two standard users to put in the network
  let alice:User = "Alice","a123",new ECDiffieHellmanCng()
  let bob:User = "Bob", "b123", new ECDiffieHellmanCng()
  let users:Users = Map.add "Bob" bob (Map.add "Alice" alice Map.empty)
  let standardNet = join alice (join bob Map.empty)
  let rec loop (network:Network) (user:User) (users:Users): int =
    let username,password,dh = user
    // write then logged in user before the cursor
    Console.Write("@" + username + " > ");
    match Console.ReadLine() with
    | "" -> 
      Console.WriteLine("Empty command.");
      loop network user users
    | "join" -> 
      Console.WriteLine("Enter new hostname:");
      let newUsername = Console.ReadLine()
      Console.WriteLine("Enter new password:");
      let newPassword = Console.ReadLine()
      let newUser = (newUsername, newPassword, new ECDiffieHellmanCng())
      let newUsers = Map.add newUsername newUser users 
      let net = join newUser network
      Console.WriteLine("Added.");
      loop net newUser newUsers
    | "login" -> 
      Console.WriteLine("Enter username:");
      let username = Console.ReadLine()
      Console.WriteLine("Enter password:");
      let password = Console.ReadLine()
      match Map.tryFind username users with
      | Some (newUsername, newPassword, dh) ->
        if newPassword = password
        then loop network (newUsername, newPassword, dh) users
        else Console.WriteLine("Wrong password!"); loop network user users
      | None -> Console.WriteLine("User not found!"); loop network user users
    | "send" -> 
      Console.WriteLine("Enter receiver name:");
      let receiver = Console.ReadLine()
      Console.WriteLine("Enter message:");
      let message = Console.ReadLine()
      let status, net = send message user receiver network
      Console.WriteLine(status);
      loop net user users
    | "read" ->
      Console.WriteLine("Who's the message from?");
      let author = Console.ReadLine()
      let message, network = receive user author network
      match message with
      | Some m -> 
        Console.WriteLine(m);
        loop network user users
      | None -> 
        Console.WriteLine("Host not found or no messages for host.");
        loop network user users
    | "quit" -> 0
    | _ -> 
      Console.WriteLine("Command not understood.");
      loop network user users
  loop standardNet alice users
  
[<EntryPoint>]
let main argv =
    Console.WriteLine("Running tests...")
    Console.WriteLine(if crypto_test_shortmessage then "Passed" else "Failed")
    Console.WriteLine(if crypto_test_2rounds then "Passed" else "Failed")
    Console.WriteLine(if crypto_test_14rounds then "Passed" else "Failed")
    Console.WriteLine(if crypto_test_enc1 then "Passed" else "Failed")
    Console.WriteLine(if crypto_test_enc2 then "Passed\n" else "Failed\n")
    
    program argv