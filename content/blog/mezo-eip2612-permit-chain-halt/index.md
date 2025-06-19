---
title: "Mezo: Attacker Can Halt the Chain via EIP-2612 Permit"
date: "2025-06-19"
description: "Mezo: Attacker Can Halt the Chain via EIP-2612 Permit"
tags: ["Cosmos", "Mezo", "Audit Competition", "DOS"]
---

## Background

- **EIP-2612 Permit** – an “approval-by-signature” scheme that lets a holder authorize ERC-20 allowances by offline signing, without first sending an on-chain `approve`.
- **Mezo precompiles** – to remain Ethereum-compatible, Mezo exposes a set of EVM precompile contracts; `precompile/erc20/permit.go` implements EIP-2612.
- **Consensus requirement** – every Cosmos-SDK validator must produce identical state transitions for the same transaction. Any non-determinism tied to local settings, system clocks, or hardware breaks this guarantee.

## Vulnerability

`Run` is the entry point for the EIP-2612 `permit` precompile. It fetches the current time and checks the deadline:

```go
func (am *PermitMethod) Run(
    context *precompile.RunContext,
    inputs  precompile.MethodInputs,
) (precompile.MethodOutputs, error) {
    timestamp := time.Now().Unix()          // ← local wall-clock time

    ...
    deadline, ok := inputs[3].(*big.Int)
    ...
    // reject if deadline has passed
    if deadline.Int64() < timestamp {       // strict `<` comparison
        return nil, fmt.Errorf("permit expired")
    }
    ...
    return precompile.MethodOutputs{true}, nil
}
```

The code relies on **`time.Now()`**, which differs across validators because of NTP drift, timezone settings, or container isolation. The strict `<` comparison (non-inclusive) widens the “gray zone” near the deadline. If a permit transaction lands milliseconds before expiry:

- **Validator A** (clock slightly slow): `timestamp < deadline` → permit **succeeds**.
- **Validator B** (clock slightly fast): `timestamp ≥ deadline` → permit **reverts**.

The two nodes disagree on nonce and allowance, producing divergent state roots; Tendermint then fails to gather a 2 / 3 majority, causing a halt or fork.

### Exploit outline

1. Attacker signs a permit with `deadline = current block time + 1 second`.
2. Network latency ensures the tx is included within a few-hundred-millisecond window before deadline.
3. Clock skew among validators triggers the split described above, breaking consensus.

## Recommendation

Use the block timestamp—already agreed upon by consensus—instead of the local system clock, and make the comparison inclusive:

```go
timestamp := context.SdkCtx().BlockTime().Unix()   // deterministic
if deadline.Int64() <= timestamp {                 // inclusive check
    return nil, fmt.Errorf("permit expired")
}
```