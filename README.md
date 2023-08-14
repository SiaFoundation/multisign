# multisign

`multisign` is a utility for spending Foundation subsidy outputs, as well as
updating the subsidy addresses.

## Generating a Seed

Run `multisign seed` to generate a random seed. Note that `multisign` uses
12-word BIP-39 seeds, not 28-word `siad` seeds.

## Deriving a Public Key

Run `multisign pubkey 0` to derive pubkey 0 from your seed.

## Constructing Multisig Unlock Conditions

To construct an m-of-n multisig address, each participant must run `multisign pubkey`
(or derive a public key some other way). Then run `multisig addr 0 2 pk1,pk2,pk3` to
construct the unlock conditions and derive the address. In this case, the multisig is
2-of-3 with no timelock.

## Creating a Transaction

Use the `multisign txn txn.json` command to run the transaction construction
wizard, which will prompt you for all relevant transaction details, including
updates to the subsidy addresses (if desired). The transaction will be written
to disk in JSON format.

## Signing a Transaction

Run `multisign sign txn.json` to add one signature to the transaction stored in
`txn.json`. The key is selected automatically from the provided seed.

## Broadcasting a Transaction

Run `multisign broadcast txn.json http://walrus.server` to broadcast `txn.json`
via the provided `walrus` server.
