package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/CornMars2020/hdkey"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

var wif string = ""
var mnemonic string = ""
var password string = ""

func init() {
	flag.StringVar(&wif, "wif", "", "Wallet Import Format Private Key")
	flag.StringVar(&mnemonic, "mnemonic", "", "Mnemonic")
	flag.StringVar(&password, "password", "", "Password")
	flag.Parse()

	mnemonic = strings.TrimSpace(mnemonic)
	re, _ := regexp.Compile("[ \t]+")
	mnemonic = re.ReplaceAllString(mnemonic, " ")

	words := strings.Split(mnemonic, " ")
	if mnemonic != "" && len(words) != 12 && len(words) != 24 {
		log.Fatal("Invalid mnemonic")
		mnemonic = ""
	}
}

func main() {
	compress := true
	count := 10
	network := "mainnet"

	if wif != "" {
		var networkParams *chaincfg.Params
		switch network {
		case "test", "testnet", "testnet3":
			networkParams = &chaincfg.TestNet3Params
		case "regtest":
			networkParams = &chaincfg.RegressionNetParams
		default:
			networkParams = &chaincfg.MainNetParams
		}

		wif, err := btcutil.DecodeWIF(wif)
		if err != nil {
			log.Fatal(err)
		}

		wifCompressed, addressCompressed, segwitBech32, segwitNested, taproot, err := hdkey.CalculateFromPrivateKey(wif.PrivKey, true, networkParams)
		if err != nil {
			log.Fatal(err)
		}

		wifUncompressed, addressUncompressed, _, _, _, err := hdkey.CalculateFromPrivateKey(wif.PrivKey, false, networkParams)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("\n Wallet Import Format:")
		fmt.Printf(" *   %-24s %s\n", "WIF(compressed):", wifCompressed)
		fmt.Printf(" *   %-24s %s\n", "WIF(uncompressed):", wifUncompressed)

		fmt.Println("\n Public Addresses:")
		fmt.Printf(" *   %-24s %s\n", "Legacy(compresed):", addressCompressed)
		fmt.Printf(" *   %-24s %s\n", "Legacy(uncompressed):", addressUncompressed)
		fmt.Printf(" *   %-24s %s\n", "SegWit(nested):", segwitNested)
		fmt.Printf(" *   %-24s %s\n", "SegWit(bech32):", segwitBech32)
		fmt.Printf(" *   %-24s %s\n", "Taproot(bech32m):", taproot)
		fmt.Println()
		return
	}

	km, err := hdkey.NewKeyManager(mnemonic, password, network)
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

	fmt.Printf("\n%-18s %-34s %-52s\n", "Path(BIP44)", "Legacy(P2PKH, compresed)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 106))
	for i := 0; i < count; i++ {
		key, err := km.GetKey(hdkey.PurposeBIP44, hdkey.CoinTypeBTC, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, address, _, _, _, err := key.Calculate(compress)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %-34s %s\n", key.Path, address, wif)
	}

	fmt.Printf("\n%-18s %-34s %s\n", "Path(BIP49)", "SegWit(P2WPKH-nested-in-P2SH)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 106))
	for i := 0; i < count; i++ {
		key, err := km.GetKey(hdkey.PurposeBIP49, hdkey.CoinTypeBTC, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, _, _, segwitNested, _, err := key.Calculate(compress)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.Path, segwitNested, wif)
	}

	fmt.Printf("\n%-18s %-42s %s\n", "Path(BIP84)", "SegWit(P2WPKH, bech32)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 114))
	for i := 0; i < count; i++ {
		key, err := km.GetKey(hdkey.PurposeBIP84, hdkey.CoinTypeBTC, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, _, segwitBech32, _, _, err := key.Calculate(compress)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.Path, segwitBech32, wif)
	}

	fmt.Printf("\n%-18s %-62s %s\n", "Path(BIP86)", "Taproot(P2TR, bech32m)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 134))
	for i := 0; i < count; i++ {
		key, err := km.GetKey(hdkey.PurposeBIP86, hdkey.CoinTypeBTC, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, _, _, _, taproot, err := key.Calculate(compress)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.Path, taproot, wif)
	}

	fmt.Printf("\n%-18s %-42s %-52s\n", "Path(BIP44)", "Ethereum(EIP55)", "Private Key(hex)")
	fmt.Println(strings.Repeat("-", 126))
	for i := 0; i < count; i++ {
		key, err := km.GetKey(hdkey.PurposeBIP44, hdkey.CoinTypeETH, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}

		address := hdkey.EthereumAddress(key.Bip32Key.Key)
		fmt.Printf("%-18s %s %x\n", key.Path, address, key.Bip32Key.Key)
	}

	fmt.Println()
}
