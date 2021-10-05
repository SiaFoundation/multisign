package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"gitlab.com/NebulousLabs/bolt"
	"gitlab.com/NebulousLabs/encoding"
	"go.sia.tech/siad/crypto"
	"go.sia.tech/siad/persist"
	"go.sia.tech/siad/types"
	"golang.org/x/term"
	"lukechampine.com/flagg"
	"lukechampine.com/us/ed25519hash"
	"lukechampine.com/us/wallet"
	"lukechampine.com/walrus"
)

var (
	rootUsage = `Usage:
    multisign [flags] [action]

Actions:
    seed            generate a seed
    pubkey          derive a pubkey
    addr            derive a multisig address
    outputs         list unspent subsidy outputs
    txn             create a transaction
    sign            add a signature to a subsidy transaction
    check           print transaction details
    broadcast       broadcast a subsidy transaction
`
	versionUsage = rootUsage
	seedUsage    = `Usage:
    multisign seed

Generates a random seed.
`
	pubkeyUsage = `Usage:
    multisign pubkey [key index]

Derives a pubkey from a seed and a key index.
`
	addrUsage = `Usage:
    multisign addr [timelock] [m] [pubkey1, pubkey2, ...]

Generates a multisig address for receiving subsidies.
`
	outputsUsage = `Usage:
    multisign outputs [consensus.db]

Lists unspent subsidy outputs in the specified consensus set.
`
	txnUsage = `Usage:
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
    multisign broadcast [file] [walrus server]

Broadcasts the provided transaction.
`
)

func main() {
	log.SetFlags(0)
	rootCmd := flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, rootUsage)
	seedCmd := flagg.New("seed", seedUsage)
	pubkeyCmd := flagg.New("pubkey", pubkeyUsage)
	addrCmd := flagg.New("addr", addrUsage)
	outputsCmd := flagg.New("outputs", outputsUsage)
	txnCmd := flagg.New("txn", txnUsage)
	signCmd := flagg.New("sign", signUsage)
	checkCmd := flagg.New("check", checkUsage)
	broadcastCmd := flagg.New("broadcast", broadcastUsage)

	cmd := flagg.Parse(flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: seedCmd},
			{Cmd: pubkeyCmd},
			{Cmd: addrCmd},
			{Cmd: outputsCmd},
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

	case seedCmd:
		if len(args) != 0 {
			cmd.Usage()
			return
		}
		fmt.Println(wallet.NewSeed())

	case pubkeyCmd:
		if len(args) != 1 {
			cmd.Usage()
			return
		}
		index, err := strconv.ParseUint(args[0], 10, 32)
		check(err, "Invalid index")
		fmt.Println(getSeed().PublicKey(index))

	case addrCmd:
		if len(args) != 3 {
			cmd.Usage()
			return
		}
		timelock, err := strconv.ParseUint(args[0], 10, 64)
		check(err, "Invalid timelock")
		m, err := strconv.ParseUint(args[1], 10, 32)
		check(err, "Invalid m")
		var keys []types.SiaPublicKey
		for _, s := range strings.Split(args[2], ",") {
			var spk types.SiaPublicKey
			err = spk.LoadString(s)
			check(err, "Invalid pubkey")
			keys = append(keys, spk)
		}
		if m > uint64(len(keys)) {
			log.Fatal("m cannot be greater than number of keys")
		}
		uc := types.UnlockConditions{
			Timelock:           types.BlockHeight(timelock),
			SignaturesRequired: m,
			PublicKeys:         keys,
		}
		js, _ := json.MarshalIndent(jsonUnlockConditions(uc), "", "  ")
		fmt.Println(string(js))
		fmt.Println(uc.UnlockHash())

	case outputsCmd:
		if len(args) != 1 {
			cmd.Usage()
			return
		}
		listOutputs(args[0])

	case txnCmd:
		if len(args) != 1 {
			cmd.Usage()
			return
		}
		txn := runTxnWizard()
		writeTxn(args[0], txn)
		fmt.Println("Wrote unsigned transaction to", args[0])

	case signCmd:
		if len(args) != 1 {
			cmd.Usage()
			return
		}
		txn := readTxn(args[0])
		if err := txn.StandaloneValid(types.FoundationHardforkHeight + 1); err == nil {
			fmt.Println("Transaction is already fully signed.")
			return
		} else if err != types.ErrMissingSignatures {
			log.Fatalln("Transaction is invalid:", err)
		}

		if !sign(&txn, getSeed()) {
			log.Fatal("Seed did not correspond to any missing signatures.")
		}
		writeTxn(args[0], txn)
		fmt.Println("Signature added successfully.")
		if txn.StandaloneValid(types.FoundationHardforkHeight+1) == nil {
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
		txn := readTxn(args[0])
		check(txn.StandaloneValid(types.FoundationHardforkHeight+1), "Transaction is standalone-invalid")

		err := walrus.NewClient(args[1]).Broadcast([]types.Transaction{txn})
		check(err, "Broadcast failed")
		fmt.Println("Transaction broadcast successfully.")
		fmt.Println("Transaction ID:", txn.ID())
	}
}

type jsonUnlockConditions types.UnlockConditions

func (uc jsonUnlockConditions) MarshalJSON() ([]byte, error) {
	s := struct {
		Timelock           types.BlockHeight `json:"timelock,omitempty"`
		PublicKeys         []string          `json:"publicKeys"`
		SignaturesRequired uint64            `json:"signaturesRequired"`
	}{uc.Timelock, make([]string, len(uc.PublicKeys)), uc.SignaturesRequired}
	for i := range s.PublicKeys {
		s.PublicKeys[i] = uc.PublicKeys[i].Algorithm.String() + ":" + hex.EncodeToString(uc.PublicKeys[i].Key)
	}
	return json.Marshal(s)
}

func check(err error, ctx string) {
	if err != nil {
		log.Fatalf("%v: %v", ctx, err)
	}
}

func readTxn(filename string) types.Transaction {
	js, err := ioutil.ReadFile(filename)
	check(err, "Could not read transaction file")
	var txn types.Transaction
	err = json.Unmarshal(js, &txn)
	check(err, "Could not parse transaction file")
	return txn
}

func writeTxn(filename string, txn types.Transaction) {
	js, _ := json.MarshalIndent(walrus.JSONTransaction(txn), "", "  ")
	js = append(js, '\n')
	err := ioutil.WriteFile(filename, js, 0666)
	check(err, "Could not write transaction to disk")
}

func getSeed() wallet.Seed {
	fmt.Print("Seed: ")
	phrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	check(err, "Could not read seed phrase")
	fmt.Println()
	seed, err := wallet.SeedFromPhrase(string(phrase))
	check(err, "Invalid seed")
	return seed
}

func sign(txn *types.Transaction, seed wallet.Seed) bool {
	// consider first 10k keys
	keys := make(map[string]ed25519.PrivateKey)
	for i := uint64(0); i < 10e3; i++ {
		sk := seed.SecretKey(i)
		keys[string(ed25519hash.ExtractPublicKey(sk))] = sk
	}

outer:
	for _, in := range txn.SiacoinInputs {
		for index, spk := range in.UnlockConditions.PublicKeys {
			if key, ok := keys[string(spk.Key)]; ok {
				// check for existing signature
				for _, sig := range txn.TransactionSignatures {
					if sig.ParentID == crypto.Hash(in.ParentID) && sig.PublicKeyIndex == uint64(index) {
						continue outer
					}
				}

				wallet.AppendTransactionSignature(txn, types.TransactionSignature{
					ParentID:       crypto.Hash(in.ParentID),
					CoveredFields:  types.FullCoveredFields,
					PublicKeyIndex: uint64(index),
				}, key)
				return true
			}
		}
	}
	return false
}

func foundationOutput(tx *bolt.Tx, height types.BlockHeight) (id types.SiacoinOutputID, sco types.SiacoinOutput, spent bool) {
	var bid types.BlockID
	encoding.Unmarshal(tx.Bucket([]byte("BlockPath")).Get(encoding.Marshal(height)), &bid)
	id = bid.FoundationSubsidyID()
	spent = encoding.Unmarshal(tx.Bucket([]byte("SiacoinOutputs")).Get(id[:]), &sco) != nil
	return
}

func listOutputs(consensusPath string) {
	_, err := os.Stat(consensusPath)
	check(err, "Could not open consensus.db")
	db, err := persist.OpenDatabase(persist.Metadata{
		Header:  "Consensus Set Database",
		Version: "0.5.0",
	}, consensusPath)
	check(err, "Could not open consensus.db")

	fmt.Println("Outputs:")
	db.View(func(tx *bolt.Tx) error {
		var currentHeight types.BlockHeight
		encoding.Unmarshal(tx.Bucket([]byte("BlockHeight")).Get([]byte("BlockHeight")), &currentHeight)
		for height := types.FoundationHardforkHeight; height < currentHeight; height += types.FoundationSubsidyFrequency {
			id, sco, spent := foundationOutput(tx, height)
			if !spent {
				fmt.Printf("Block %6v: %v %v (%v SC)\n", height, id, sco.UnlockHash, sco.Value.Div(types.SiacoinPrecision))
			}
		}
		return nil
	})
}

func ask(prompt string) (resp string) {
	fmt.Print(prompt + ": ")
	fmt.Scanln(&resp)
	return
}

func parseCurrency(s string, c *types.Currency) bool {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(s))
	if !ok {
		return false
	}
	*c = types.SiacoinPrecision.MulRat(r)
	return true
}

func runTxnWizard() (txn types.Transaction) {
	// inputs
	fmt.Println("--- Inputs ---")
	var inputSum types.Currency
	for {
		idStr := ask("ID (or 'done')")
		if idStr == "done" {
			break
		}
		var in types.SiacoinInput
		if (*crypto.Hash)(&in.ParentID).LoadString(idStr) != nil {
			fmt.Println("Invalid ID")
			continue
		}
		ucStr := ask("UnlockConditions (as JSON, no whitespace)")
		if json.Unmarshal([]byte(ucStr), &in.UnlockConditions) != nil {
			fmt.Println("Invalid UnlockConditions")
			continue
		}
		valueStr := ask("Value (in SC)")
		var v types.Currency
		if !parseCurrency(valueStr, &v) {
			fmt.Println("Invalid value")
			continue
		}
		txn.SiacoinInputs = append(txn.SiacoinInputs, in)
		inputSum = inputSum.Add(v)
	}
	// outputs
	fmt.Println("--- Outputs ---")
	var outputSum types.Currency
	for {
		addrStr := ask("Address (or 'done')")
		if addrStr == "done" {
			break
		}
		var out types.SiacoinOutput
		if out.UnlockHash.LoadString(addrStr) != nil {
			fmt.Println("Invalid address")
			continue
		}
		amountStr := ask("Amount (in SC)")
		if !parseCurrency(amountStr, &out.Value) {
			fmt.Println("Invalid amount")
			continue
		}
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, out)
		outputSum = outputSum.Add(out.Value)
		if outputSum.Cmp(inputSum) > 0 {
			log.Fatal("Invalid transaction: outputs exceed inputs")
		}
	}
	fee := inputSum.Sub(outputSum)
	if fee.IsZero() {
		fmt.Println("Warning: outputs exactly equal inputs; miner fee will be zero")
	} else {
		fmt.Printf("Remaining input value (%v SC) will be used as miner fee.\n", fee.Div(types.SiacoinPrecision))
		txn.MinerFees = append(txn.MinerFees, fee)
	}

	resp := strings.ToLower(ask("Include a subsidy address update in this transaction? [y/n]"))
	if resp == "y" || resp == "yes" {
		var update types.FoundationUnlockHashUpdate
		if update.NewPrimary.LoadString(ask("New Primary Address")) != nil {
			log.Fatal("Invalid address")
		}
		if update.NewFailsafe.LoadString(ask("New Failsafe Address")) != nil {
			log.Fatal("Invalid address")
		}
		txn.ArbitraryData = append(txn.ArbitraryData, encoding.MarshalAll(types.SpecifierFoundation, update))
	}

	return txn
}

func checkTxn(txn types.Transaction) {
	fmt.Println("Transaction summary:")
	fmt.Println()
	fmt.Println("ID:   ", txn.ID())
	if err := txn.StandaloneValid(types.FoundationHardforkHeight + 1); err == nil {
		fmt.Println("Valid: Yes")
	} else {
		fmt.Printf("Valid: No (%v)\n", err)
	}
	fmt.Println()

	fmt.Println("Inputs:")
	for _, in := range txn.SiacoinInputs {
		fmt.Println("  ID:  ", in.ParentID)
		fmt.Println("  Addr:", in.UnlockConditions.UnlockHash())
	}
	fmt.Println()
	fmt.Println("Outputs:")
	for _, out := range txn.SiacoinOutputs {
		dest := "to"
		for _, in := range txn.SiacoinInputs {
			if in.UnlockConditions.UnlockHash() == out.UnlockHash {
				dest = "returned to input"
				break
			}
		}
		fmt.Printf("  %8v %v %v\n", out.Value.HumanString(), dest, out.UnlockHash)
	}
	fmt.Println()
	var minerFee types.Currency
	for _, fee := range txn.MinerFees {
		minerFee = minerFee.Add(fee)
	}
	fmt.Println("Miner Fee:", minerFee.HumanString())
	fmt.Println()
	// check for update
	for _, arb := range txn.ArbitraryData {
		if bytes.HasPrefix(arb, types.SpecifierFoundation[:]) {
			var update types.FoundationUnlockHashUpdate
			if err := encoding.Unmarshal(arb[types.SpecifierLen:], &update); err != nil {
				fmt.Println("WARNING: transaction contains invalid Foundation unlock hash update")
				continue
			}
			fmt.Println("Foundation Unlock Hash Update:")
			fmt.Println("New Primary: ", update.NewPrimary)
			fmt.Println("New Failsafe:", update.NewFailsafe)
			fmt.Println()
		} else {
			fmt.Println("WARNING: transaction contains unrecognized arbitrary data")
		}
	}
	// check for other non-standard fields
	if len(txn.FileContracts) != 0 {
		fmt.Println("WARNING: transaction contains file contract(s)")
	}
	if len(txn.FileContractRevisions) != 0 {
		fmt.Println("WARNING: transaction contains file contract revision(s)")
	}
	if len(txn.StorageProofs) != 0 {
		fmt.Println("WARNING: transaction contains storage proof(s)")
	}
	if len(txn.SiafundInputs) != 0 {
		fmt.Println("WARNING: transaction contains siafund input(s)")
	}
	if len(txn.SiafundOutputs) != 0 {
		fmt.Println("WARNING: transaction contains siafund output(s)")
	}

	// validate signatures
	ucMap := make(map[crypto.Hash]types.UnlockConditions)
	for _, in := range txn.SiacoinInputs {
		ucMap[crypto.Hash(in.ParentID)] = in.UnlockConditions
	}
	for _, in := range txn.SiafundInputs {
		ucMap[crypto.Hash(in.ParentID)] = in.UnlockConditions
	}
	for _, rev := range txn.FileContractRevisions {
		ucMap[crypto.Hash(rev.ParentID)] = rev.UnlockConditions
	}
	fmt.Println("Signatures:")
	for i, sig := range txn.TransactionSignatures {
		uc, ok := ucMap[sig.ParentID]
		if !ok {
			fmt.Printf("  INVALID signature on %v: no transaction element with that ID\n", sig.ParentID)
			continue
		} else if sig.PublicKeyIndex >= uint64(len(uc.PublicKeys)) {
			fmt.Printf("  INVALID signature on %v: public key index is out-of-bounds\n", sig.ParentID)
			continue
		}
		spk := uc.PublicKeys[sig.PublicKeyIndex]
		sigHash := txn.SigHash(i, types.FoundationHardforkHeight+1)
		if spk.Algorithm != types.SignatureEd25519 || !ed25519hash.Verify(spk.Key, sigHash, sig.Signature) {
			fmt.Println("  INVALID signature from key", spk)
			fmt.Println("                          on", sig.ParentID)
			continue
		}
		fmt.Println("  Valid signature from key", spk)
		fmt.Println("                        on", sig.ParentID)
		if !sig.CoveredFields.WholeTransaction {
			fmt.Println("    (WARNING: signature does not cover whole transaction)")
		}
	}
	if len(txn.TransactionSignatures) == 0 {
		fmt.Println("  Transaction has no signatures")
	}
}
