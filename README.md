# hdkey

Hdkey Gen for Bitcoin and Ethereum

## Generate New HD Wallet

```go
km, err := hdkey.NewKeyManager(mnemonic, password)
if err != nil {
  log.Fatal(err)
}
masterKey, err := km.GetMasterKey()
if err != nil {
  log.Fatal(err)
}
passphrase := km.Passphrase
if passphrase == "" {
  passphrase = "<none>"
}
fmt.Printf("\n%-18s %s\n", "BIP39 Mnemonic:", km.Mnemonic)
fmt.Printf("%-18s %s\n", "BIP39 Passphrase:", passphrase)
fmt.Printf("%-18s %x\n", "BIP39 Seed:", km.GetSeed())
fmt.Printf("%-18s %s\n", "BIP32 Root Key:", masterKey.B58Serialize())
```

### Get Address and WIF PrivKey

```go
// Purpose Version, CoinType
key, err := km.GetKey(hdkey.PurposeBIP44, hdkey.CoinTypeBTC, 0, 0, uint32(i))
if err != nil {
  log.Fatal(err)
}

// Address and WIF
wif, address, _, _, _, err := key.Calculate(compress)
if err != nil {
  log.Fatal(err)
}
```

## Thanks

Source code is from: <https://github.com/modood/hdkeygen/blob/master/main.go>, but the original version can only used as standalone software.

I separated the core functions and main func
