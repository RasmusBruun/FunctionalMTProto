module Test

open Network
open Format
open LookupTables
open AESencrypt
open AESdecrypt
open Transport

let crypto_test_shortmessage = 
    let message = "hello" 
    let key = "keykeykeykeykey" 
    let iv = "NotRandomInitializationVector"
    let rounds = 14
    let actual = DecryptStringWith (EncryptStringWith message key iv rounds).Value key iv rounds
    actual.Value = message

let crypto_test_2rounds = 
    let message = "the big brown wolf jumps over the lazy dog" 
    let key = "keykeykeykeykey" 
    let iv = "NotRandomInitializationVector"
    let rounds = 2
    let actual = DecryptStringWith (EncryptStringWith message key iv rounds).Value key iv rounds
    actual.Value = message

let crypto_test_14rounds = 
    let message = "the big brown wolf jumps over the lazy dog" 
    let key = "keykeykeykeykey" 
    let iv = "NotRandomInitializationVector"
    let rounds = 14
    let actual = DecryptStringWith (EncryptStringWith message key iv rounds).Value key iv rounds
    actual.Value = message

let crypto_test_enc1 = 
    let message = "lorem ipsum dolor sit amet" 
    let key = "keykeykeykeykey" 
    let iv = "NotRandomInitializationVector"
    let rounds = 14
    let actual = DecryptStringWith (EncryptStringWith (enc.GetString(enc.GetBytes message)) key iv rounds).Value key iv rounds
    actual.Value = message

let crypto_test_enc2 = 
    let message = "the big fat brown wolf doesn't want to jump over the lazy dog" 
    let key = "keykeykeykeykey" 
    let iv = "NotRandomInitializationVector"
    let rounds = 14
    let crypto = EncryptStringWith (enc.GetString(enc.GetBytes message)) key iv rounds
    let arr = [|crypto|]
    let map = Map.add 1 arr (Map.empty)
    let actual = DecryptStringWith ((Map.find 1 map).[0]).Value key iv rounds
    actual.Value = message
