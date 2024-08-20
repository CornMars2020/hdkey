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
			log.Fatal("DecodeWIF", err)
		}

		wifCompressed, serializedPubKeyHexCompressed, addressCompressed, segwitBech32, segwitNested, taproot, err := hdkey.CalculateFromPrivateKey(wif.PrivKey, true, networkParams)
		if err != nil {
			log.Fatal("Calculate", err)
		}

		wifUncompressed, serializedPubKeyHexUncompressed, addressUncompressed, _, _, _, err := hdkey.CalculateFromPrivateKey(wif.PrivKey, false, networkParams)
		if err != nil {
			log.Fatal("Calculate Uncompressed", err)
		}

		fmt.Println("\n Wallet Import Format:")
		fmt.Printf(" *   %-24s %s\n", "WIF(compressed):", wifCompressed)
		fmt.Printf(" *   %-24s %s\n", "WIF(uncompressed):", wifUncompressed)

		fmt.Println("\n Public Key:")
		fmt.Printf(" *   %-24s %s\n", "Compressed:", serializedPubKeyHexCompressed)
		fmt.Printf(" *   %-24s %s\n", "Uncompressed:", serializedPubKeyHexUncompressed)

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
		log.Fatal("NewKeyManager", err)
	}
	masterKey, err := km.GetMasterKey()
	if err != nil {
		log.Fatal("GetMasterKey", err)
	}
	passphrase := km.Passphrase
	if passphrase == "" {
		passphrase = "<none>"
	}
	fmt.Printf("\n%-18s %s\n", "BIP39 Mnemonic:", km.Mnemonic)
	fmt.Printf("%-18s %s\n", "BIP39 Passphrase:", passphrase)
	fmt.Printf("%-18s %x\n", "BIP39 Seed:", km.GetSeed())
	fmt.Printf("%-18s %s\n", "BIP32 Root Key:", masterKey.B58Serialize())

	fmt.Printf("\n%-18s %-34s %-52s %-66s\n", "Path(BIP44)", "Legacy(P2PKH, compresed)", "WIF(Wallet Import Format)", "Public Key")
	fmt.Println(strings.Repeat("-", 173))
	for i := 0; i < count; i++ {
		key, err := km.GetBTCLegacyKey(uint32(i))
		if err != nil {
			log.Fatal("GetKey Path(BIP44)", err)
		}
		wif, serializedPubKeyHex, address, _, _, _, err := key.Calculate(compress)
		if err != nil {
			log.Fatal("Calculate Path(BIP44)", err)
		}

		fmt.Printf("%-18s %-34s %-52s %-66s\n", key.Path, address, wif, serializedPubKeyHex)
	}

	fmt.Printf("\n%-18s %-34s %-52s %-66s\n", "Path(BIP49)", "Nested SegWit(P2WPKH-nested-in-P2SH)", "WIF(Wallet Import Format)", "Public Key")
	fmt.Println(strings.Repeat("-", 173))
	for i := 0; i < count; i++ {
		key, err := km.GetBTCNestedSegWitKey(uint32(i))
		if err != nil {
			log.Fatal("GetKey Path(BIP49)", err)
		}
		wif, serializedPubKeyHex, _, _, segwitNested, _, err := key.Calculate(compress)
		if err != nil {
			log.Fatal("Calculate Path(BIP49)", err)
		}

		fmt.Printf("%-18s %-34s %-52s %-66s\n", key.Path, segwitNested, wif, serializedPubKeyHex)
	}

	fmt.Printf("\n%-18s %-42s %-52s %-66s\n", "Path(BIP84)", "Native SegWit(P2WPKH, bech32)", "WIF(Wallet Import Format)", "Public Key")
	fmt.Println(strings.Repeat("-", 181))
	for i := 0; i < count; i++ {
		key, err := km.GetBTCNativeSegWitKey(uint32(i))
		if err != nil {
			log.Fatal("GetKey Path(BIP84)", err)
		}
		wif, serializedPubKeyHex, _, segwitBech32, _, _, err := key.Calculate(compress)
		if err != nil {
			log.Fatal("Calculate Path(BIP84)", err)
		}

		fmt.Printf("%-18s %-42s %-52s %-66s\n", key.Path, segwitBech32, wif, serializedPubKeyHex)
	}

	fmt.Printf("\n%-18s %-62s %-52s %-66s\n", "Path(BIP86)", "Taproot(P2TR, bech32m)", "WIF(Wallet Import Format)", "Public Key")
	fmt.Println(strings.Repeat("-", 201))
	for i := 0; i < count; i++ {
		key, err := km.GetBTCTaprootKey(uint32(i))
		if err != nil {
			log.Fatal("GetKey Path(BIP86)", err)
		}
		wif, serializedPubKeyHex, _, _, _, taproot, err := key.Calculate(compress)
		if err != nil {
			log.Fatal("Calculate Path(BIP86)", err)
		}

		fmt.Printf("%-18s %-62s %-52s %-66s\n", key.Path, taproot, wif, serializedPubKeyHex)
	}

	fmt.Printf("\n%-18s %-42s %-52s\n", "Path(BIP44)", "Ethereum(EIP55)", "Private Key(hex)")
	fmt.Println(strings.Repeat("-", 126))
	for i := 0; i < count; i++ {
		key, err := km.GetKey(hdkey.PurposeBIP44, hdkey.CoinTypeETH, 0, 0, uint32(i))
		if err != nil {
			log.Fatal("GetKey Path(BIP44)", err)
		}

		address := hdkey.EthereumAddress(key.Bip32Key.Key)
		fmt.Printf("%-18s %s %x\n", key.Path, address, key.Bip32Key.Key)
	}

	fmt.Println()
}
