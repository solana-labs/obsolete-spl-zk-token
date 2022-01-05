
# Confidential Token Program
This program is a companion to the SPL Token program that enables confidential
(**not** anonymous) transfers of SPL Tokens.

Any SPL Token can take enable confidential transfers. However SPL Tokens with a
freeze authority can optionally enable a feature that allows a global auditor to
also view all confidential transfer balances, and the freeze authority extends
to confidential token accounts.

The overview and the description of the cryptographic protocol can be found in
the work-in-progress documents [part1](/paper/part1.pdf) and
[part2](paper/part2.pdf).

## Development Environment

### Setup
A master branch of the Solana monorepo is required for development.

Then clone this repository, then run
```
$ ./setup.sh
```

### Transfer Demo

To run the simple confidential transfer demo, first build the BPF program:
```
$ cd ./program/
$ cargo build-bpf
```

Then start the `solana-test-validator`:
```
$ ./solana/validator/solana-test-validator --reset --limit-ledger-size 500000000 \
    --bpf-program ZkTokenXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNg1 \
    target/deploy/spl_zk_token.so
```

Finally in another shell, run:
```
$ cd ./demo/
$ cargo run -- -ul
```

## Use cases

### Enabling confidential transfers for an SPL Token mint
Before a confidential transfers may be used on a given SPL Token, the
`ConfidentialTokenInstruction::ConfigureMint` instruction must be executed.
Depending on the configuration of the SPL Token, this instruction may either be
permissionless or require the Mint's freeze authority to sign.

`ConfidentialTokenInstruction::ConfigureMint` notably creates the single omnibus
token account used to store all SPL Tokens deposited into the confidential token
accounts.

Note: As there is one omnibus token account for each token mint, confidential
token deposits and withdrawals for a given SPL Token will be implicitly
serialized by the runtime during transaction execution. An alternative would be
for each SPL Token to have several omnibus token accounts that users could
random select for deposits and withdrawals.  However this complicates
withdrawals in particular, as now clients need to potentially check multiple
omnibus accounts to to find one with sufficient funds for the withdrawal. A
rebalancing scheme between multiple omnibus accounts would likely be needed as
well.

### Determining if confidential transfers has been enabled for an SPL Token mint
Check for the existence of the omnibus SPL Token account. Use
`get_omnibus_token_address()` to derive its address for an SPL Token mint.  The
token balance of the omnibus account contains the total number of tokens that
have been deposited into the confidential transfer system

Reading the contents of the `get_transfer_auditor_address()` account will
indicate if a transfer auditor is enabled for the SPL Token mint. If so, all
confidential transfers for the SPL Token must include additional ciphertext to
allow the transfer auditor to observe the transfer amount.

### Enabling confidential transfers for a particular token holder
Once confidential transfers are enabled for a SPL Token mint, a token holder can
opt in to confidential transfers by executing the
`ConfidentialTokenInstruction::ConfigureAccount` instruction and providing their
confidential public encryption key.

The confidential token account address is a PDA derived from their normal token.

### Determining if a token holder has enabled confidential transfers
Check for the existence of the user's confidential token account.  Use
`get_confidential_token_address()` to derive its address from the user's SPL
Token account.

### Depositing funds into a confidential token account
SPL Tokens can be deposited into any confidential token account using the
`ConfidentialTokenInstruction::Deposit` instruction.

### Withdrawing funds from a confidential token account
SPL Tokens can be withdrawn from a confidential token account using the
`ConfidentialTokenInstruction::Withdraw` instruction.

### Confidential token account ownership changes
Since the confidential token account is a companion to a normal SPL Token
account, ownership changes of the SPL Token account automatically convey to the
confidential token account.

However the close authority of the SPL Token account *does not* convey to the
confidential token account.

Note that it is possible to "brick" a confidential token account by closing the
corresponding SPL Token account, as no future instructions that require the
account authority would be permitted.  This is unlikely to occur unintentionally
because the confidential token account must be created by the same wallet that
holds the SPL Token account, and therefore is already confidential token aware.

### Freezing of confidential funds
Freezing the primary SPL Token account also causes the companion confidential token account to be frozen.

### Making a confidential transfer [TODO: This section is out of date]
Multiple transactions are required to perform a confidential transfer due to the
current max the transaction size of 1232 bytes.

To affect a transfer, the sender must issue two
`ConfidentialTokenInstruction::SubmitTransferProof` instructions, in separate
transactions in parallel.  Once both transactions are confirmed they then issue
a `ConfidentialTokenInstruction::Transfer` instruction.
**These instructions are in flux and are likely to change as the design evolves**

Since the transfer process is not atomic, it's possible for multiple senders to
race during a transfer to the same recipient. In this case, one of the senders
will lose the race and will need to retry the entire transfer sequence. This
condition will be reported via a specific program error code.

Confidential transfers are not supported in cross-program invocations.
