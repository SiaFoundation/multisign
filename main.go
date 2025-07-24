package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/walletd/v2/api"
	"golang.org/x/term"
	"lukechampine.com/flagg"
)

var (
	rootUsage = `Usage:
    multisign [flags] [action]

Actions:
    txn             create a transaction
    sign            add a signature to a subsidy transaction
    check           print transaction details
    broadcast       broadcast a subsidy transaction
`
	versionUsage = rootUsage
	txnUsage     = `Usage:
    multisign txn [file]

Launches the transaction construction wizard. Upon answering all prompts, the
resulting transaction is written to the specified file. The transaction may
optionally include a subsidy address update.
`
	signUsage = `Usage:
    multisign sign [file]

Adds a signature to a subsidy transaction. The appropriate key is selected
automatically from the provided seed.
`
	checkUsage = `Usage:
    multisign check [file]

Prints transaction details, including whether any attached signatures are valid.
`
	broadcastUsage = `Usage:
    multisign broadcast [file]

Broadcasts the provided transaction.
`
)

func main() {
	log.SetFlags(0)
	rootCmd := flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, rootUsage)
	txnCmd := flagg.New("txn", txnUsage)
	signCmd := flagg.New("sign", signUsage)
	checkCmd := flagg.New("check", checkUsage)
	broadcastCmd := flagg.New("broadcast", broadcastUsage)

	cmd := flagg.Parse(flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: txnCmd},
			{Cmd: signCmd},
			{Cmd: checkCmd},
			{Cmd: broadcastCmd},
		},
	})
	args := cmd.Args()

	switch cmd {
	case rootCmd:
		if len(args) != 0 {
			cmd.Usage()
			return
		}
		log.Println("multisign v0.1.0")

	case txnCmd:
		if len(args) != 1 {
			cmd.Usage()
			return
		}
		writeTxn(args[0], runTxnWizard())
		fmt.Println("Wrote unsigned transaction to", args[0])

	case signCmd:
		if len(args) != 1 {
			cmd.Usage()
			return
		}
		set := readTxn(args[0])
		if !sign(&set, getSeed()) {
			log.Fatal("Seed did not correspond to any missing signatures.")
		}
		writeTxn(args[0], set)
		fmt.Println("Signature(s) added successfully.")
		if validate(set) == nil {
			fmt.Println("Transaction is now fully signed.")
		}

	case checkCmd:
		if len(args) != 1 {
			cmd.Usage()
			return
		}
		checkTxn(readTxn(args[0]))

	case broadcastCmd:
		if len(args) != 2 {
			cmd.Usage()
			return
		}
		js, err := os.ReadFile(args[0])
		check(err, "Could not read transaction file")
		resp, err := http.Post("http://txpool.lukechampine.com/broadcast", "application/json", bytes.NewReader(js))
		check(err, "Broadcast failed")
		if resp.StatusCode != http.StatusOK {
			errBody, _ := io.ReadAll(resp.Body)
			log.Fatalf("Broadcast failed: %s", errBody)
		}
		var ids struct {
			IDs []types.TransactionID `json:"ids"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&ids); err != nil {
			log.Fatalf("Could not decode response: %v", err)
		}
		fmt.Println("Transaction broadcast successfully.")
		fmt.Println("Transaction ID:", ids.IDs[0])
	}
}

func check(err error, ctx string) {
	if err != nil {
		log.Fatalf("%v: %v", ctx, err)
	}
}

type TransactionSet struct {
	Basis        types.ChainIndex      `json:"basis"`
	Transactions []types.V2Transaction `json:"transactions"`
}

func readTxn(filename string) (set TransactionSet) {
	js, err := os.ReadFile(filename)
	check(err, "Could not read transaction file")
	err = json.Unmarshal(js, &set)
	check(err, "Could not parse transaction file")
	return
}

func writeTxn(filename string, set TransactionSet) {
	js, _ := json.MarshalIndent(set, "", "  ")
	js = append(js, '\n')
	err := os.WriteFile(filename, js, 0666)
	check(err, "Could not write transaction to disk")
}

func getSeed() (seed *[32]byte) {
	fmt.Print("Seed: ")
	phrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	check(err, "Could not read seed phrase")
	fmt.Println()
	seed = new([32]byte)
	err = wallet.SeedFromPhrase(seed, string(phrase))
	check(err, "Invalid seed")
	return
}

func basisState(set TransactionSet) consensus.State {
	wc := api.NewClient("https://api.siascan.com/wallet", "")
	resp, err := wc.ConsensusCheckpointID(set.Basis.ID)
	check(err, "Could not fetch consensus state")
	return resp.State
}

func validate(set TransactionSet) error {
	if len(set.Transactions) != 1 {
		return fmt.Errorf("expected exactly one transaction in set")
	}
	ms := consensus.NewMidState(basisState(set))
	if err := consensus.ValidateV2Transaction(ms, set.Transactions[0]); err != nil {
		if strings.Contains(err.Error(), "threshold not reached") {
			err = fmt.Errorf("missing signatures")
		}
		return err
	}
	return nil
}

func sign(set *TransactionSet, seed *[32]byte) bool {
	cs := basisState(*set)

	// consider first 10k keys
	keys := make(map[string]types.PrivateKey)
	for i := uint64(0); i < 10e3; i++ {
		sk := wallet.KeyFromSeed(seed, i)
		keys[string(sk.PublicKey().UnlockKey().Key)] = sk
	}

	if len(set.Transactions) != 1 {
		log.Fatal("Expected exactly one transaction in set")
	}
	txn := set.Transactions[0]
	sigHash := cs.InputSigHash(txn)

	signed := false
outer:
	for i := range txn.SiacoinInputs {
		in := &txn.SiacoinInputs[i]
		uc, ok := in.SatisfiedPolicy.Policy.Type.(types.PolicyTypeUnlockConditions)
		if !ok {
			continue
		}
		for _, pk := range uc.PublicKeys {
			if key, ok := keys[string(pk.Key)]; ok {
				sig := key.SignHash(sigHash)
				for _, existing := range in.SatisfiedPolicy.Signatures {
					if existing == sig {
						continue outer // already signed
					}
				}
				in.SatisfiedPolicy.Signatures = append(in.SatisfiedPolicy.Signatures, sig)
				signed = true
			}
		}
	}
	return signed
}

func ask(prompt string) (resp string) {
	fmt.Print(prompt + ": ")
	fmt.Scanln(&resp)
	return
}

func unHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("Invalid hex string: %v", err)
	}
	return b
}

var foundationUnlockConditions = types.UnlockConditions{
	PublicKeys: []types.UnlockKey{
		{Algorithm: types.SpecifierEd25519, Key: unHex("8663398b3299ab679f3002ad2acc656e013c3b1cc4c5d7368b8da586c7e38f4f")},
		{Algorithm: types.SpecifierEd25519, Key: unHex("e9949c7a7bb0b97daaa3a567f2f876663a36f9f3b7f97b7728753ab1b2dd8284")},
	},
	SignaturesRequired: 2,
}
var foundationAddress = foundationUnlockConditions.UnlockHash()

func runTxnWizard() (set TransactionSet) {
	wc := api.NewClient("https://api.siascan.com/wallet", "")
	utxos, basis, err := wc.AddressSiacoinOutputs(foundationAddress, false, 0, 1000)
	if err != nil {
		log.Fatal(err)
	}
	set.Basis = basis
	set.Transactions = []types.V2Transaction{{}}
	txn := &set.Transactions[0]

	fmt.Println("--- Inputs ---")
	for i := range utxos {
		fmt.Printf("%3v:  %8v %v\n", i, utxos[i].SiacoinOutput.Value, utxos[i].ID)
	}
	fmt.Print("Select indices, comma-separated: ")
	indicesStr, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	var inputSum types.Currency
	for _, s := range strings.Split(indicesStr, ",") {
		i, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			log.Fatal(err)
		} else if i < 0 || i >= len(utxos) {
			log.Fatal("Invalid index")
		}
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.V2SiacoinInput{
			Parent: utxos[i].SiacoinElement,
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(foundationUnlockConditions)},
			},
		})
		inputSum = inputSum.Add(utxos[i].SiacoinOutput.Value)
	}
	fmt.Println("Total value:", inputSum)
	// outputs
	fmt.Println("--- Outputs ---")
	var outputSum types.Currency
	txn.MinerFee = types.Siacoins(10)
	outputSum = outputSum.Add(txn.MinerFee)
	for {
		addrStr := ask("Address (or 'done')")
		if addrStr == "done" {
			break
		}
		var out types.SiacoinOutput
		if out.Address.UnmarshalText([]byte(addrStr)) != nil {
			fmt.Println("Invalid address")
			continue
		}
		amountStr := ask("Amount (or 'all')")
		if amountStr == "all" {
			out.Value = inputSum.Sub(outputSum)
			txn.SiacoinOutputs = append(txn.SiacoinOutputs, out)
			outputSum = inputSum
			break
		} else if out.Value.UnmarshalText([]byte(amountStr)) != nil {
			fmt.Println("Invalid amount")
			continue
		}
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, out)
		outputSum = outputSum.Add(out.Value)
		if outputSum.Cmp(inputSum) > 0 {
			log.Fatal("Invalid transaction: outputs exceed inputs")
		}
	}

	// return change to wallet
	if change := inputSum.Sub(outputSum); !change.IsZero() {
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Value:   change,
			Address: foundationAddress,
		})
	}

	subsidy := strings.ToLower(ask("Include a subsidy address update in this transaction? [y/n]"))
	if subsidy == "y" || subsidy == "yes" {
		txn.NewFoundationAddress = new(types.Address)
		if txn.NewFoundationAddress.UnmarshalText([]byte(ask("New Address"))) != nil {
			log.Fatal("Invalid address")
		}
	}

	return
}

func checkTxn(set TransactionSet) {
	if len(set.Transactions) != 1 {
		log.Fatal("Expected exactly one transaction in set")
	}
	txn := set.Transactions[0]
	fmt.Println("Transaction summary:")
	fmt.Println()
	fmt.Println("ID:   ", txn.ID())
	if err := validate(set); err == nil {
		fmt.Println("Valid: Yes")
	} else {
		fmt.Printf("Valid: No (%v)\n", err)
	}
	fmt.Println()

	fmt.Println("Inputs:")
	for _, in := range txn.SiacoinInputs {
		fmt.Printf("  %8v from %v\n", in.Parent.SiacoinOutput.Value, in.Parent.SiacoinOutput.Address)
	}
	fmt.Println()
	fmt.Println("Outputs:")
	for _, out := range txn.SiacoinOutputs {
		dest := "to"
		for _, in := range txn.SiacoinInputs {
			if in.Parent.SiacoinOutput.Address == out.Address {
				dest = "returned to input"
				break
			}
		}
		fmt.Printf("  %8v %v %v\n", out.Value, dest, out.Address)
	}
	fmt.Println()
	fmt.Println("Miner Fee:", txn.MinerFee)
	fmt.Println()
	// check for update
	if txn.NewFoundationAddress != nil {
		fmt.Println("New Foundation Address:", *txn.NewFoundationAddress)
		fmt.Println()
	}
	// check for other non-standard fields
	if len(txn.FileContracts) != 0 {
		fmt.Println("WARNING: transaction contains file contract(s)")
	}
	if len(txn.FileContractRevisions) != 0 {
		fmt.Println("WARNING: transaction contains file contract revision(s)")
	}
	if len(txn.FileContractResolutions) != 0 {
		fmt.Println("WARNING: transaction contains file contract resolution(s)")
	}
	if len(txn.SiafundInputs) != 0 {
		fmt.Println("WARNING: transaction contains siafund input(s)")
	}
	if len(txn.SiafundOutputs) != 0 {
		fmt.Println("WARNING: transaction contains siafund output(s)")
	}

	wc := api.NewClient("https://api.siascan.com/wallet", "")
	resp, err := wc.ConsensusCheckpointID(set.Basis.ID)
	check(err, "Could not fetch consensus state")
	cs := resp.State
	sigHash := cs.InputSigHash(txn)

	// validate signatures
	fmt.Println("Signatures:")
	sci := txn.SiacoinInputs[0]
	for _, sig := range sci.SatisfiedPolicy.Signatures {
		for _, pk := range foundationUnlockConditions.PublicKeys {
			if ed25519.Verify(pk.Key, sigHash[:], sig[:]) {
				fmt.Printf("    Valid signature from %v:%x\n", pk.Algorithm, pk.Key)
			}
		}
	}
	if len(sci.SatisfiedPolicy.Signatures) == 0 {
		fmt.Println("  No signatures")
	}
}
