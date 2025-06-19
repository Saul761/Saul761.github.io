---
title: "Mantra Chain: BeforeSendHook Can Halt the Chain"
date: "2025-06-19"
description: "Mantra Chain: BeforeSendHook Can Halt the Chain"
tags: ["Cosmos", "Mantra", "Audit Competition", "DOS"]
---

In **MANTRA-Chain’s** `x/tokenfactory` module, a token creator can call `MsgSetBeforeSendHook` to attach a **BeforeSend** hook (a CosmWasm contract address) to a custom denom. Each time that denom is transferred, the chain first executes the hook via `sudo` and then decides whether to allow the transfer.

```go
func (server msgServer) SetBeforeSendHook(goCtx context.Context, msg *types.MsgSetBeforeSendHook) (*types.MsgSetBeforeSendHookResponse, error) {
    ...
    err = server.Keeper.setBeforeSendHook(ctx, msg.Denom, msg.ContractAddr) // <----------
    ...
}
```

`setBeforeSendHook` never checks whether the supplied contract address is valid or behaves correctly:

```go
func (k Keeper) setBeforeSendHook(ctx sdk.Context, denom, contractAddr string) error {
    ...
    // delete hook if address is empty
    if contractAddr == "" {
        store.Delete([]byte(types.BeforeSendHookAddressPrefixKey))
        return nil
    }

    // only Bech32 format check
    _, err = sdk.AccAddressFromBech32(contractAddr)
    if err != nil {
        return err
    }

    store.Set([]byte(types.BeforeSendHookAddressPrefixKey), []byte(contractAddr))
    return nil
}
```

An attacker can therefore register **an invalid or malicious contract address** as the hook.

## Impact

Essentially, **TokenFactory** registers its own `BankHooks` with the bank module, so every transfer first goes through `callBeforeSendListener`, which in turn triggers the attacker-supplied hook. If the hook address points to an invalid contract, each transfer fails and returns an error.

```go
func (k Keeper) callBeforeSendListener(ctx context.Context, from, to sdk.AccAddress, amount sdk.Coins, blockBeforeSend bool) (err error) {
    c := sdk.UnwrapSDKContext(ctx)

    defer func() {
        if r := recover(); r != nil {
            err = types.ErrTrackBeforeSendOutOfGas
        }
    }()

    for _, coin := range amount {
        contractAddr := k.GetBeforeSendHook(ctx, coin.Denom)
        if contractAddr != "" {
            // execute hook
        }
    }
    return nil
}
```

An attacker can first **create** a custom denom with `CreateDenom`, then **mint** tokens to themselves.

Next, they use `MsgDepositValidatorRewardsPool` to send those malicious tokens to a validator, so both the validator and its delegators have pending rewards in that denom.

Then they set an **invalid contract address** as the hook for that denom.

When an **unbond** or **reward-withdrawal** operation is performed, the chain runs `BeforeDelegationSharesModified`:

```go
// withdraw delegation rewards (which also increments period)
func (h Hooks) BeforeDelegationSharesModified(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) error {
    val, err := h.k.stakingKeeper.Validator(ctx, valAddr)
    if err != nil {
        return err
    }

    del, err := h.k.stakingKeeper.Delegation(ctx, delAddr, valAddr)
    if err != nil {
        return err
    }

    if _, err := h.k.withdrawDelegationRewards(ctx, val, del); err != nil { // <---
        return err
    }

    return nil
}
```

`BeforeDelegationSharesModified` invokes `withdrawDelegationRewards`, which triggers the malicious hook and causes every unbond or reward withdrawal to fail:

```go
func (k Keeper) withdrawDelegationRewards(ctx context.Context, val stakingtypes.ValidatorI, del stakingtypes.DelegationI) (sdk.Coins, error) {
    addrCodec := k.authKeeper.AddressCodec()
    delAddr, err := addrCodec.StringToBytes(del.GetDelegatorAddr())
    ...

    // add coins to user account
    if !finalRewards.IsZero() {
        withdrawAddr, err := k.GetDelegatorWithdrawAddr(ctx, delAddr)
        if err != nil {
            return nil, err
        }

        err = k.bankKeeper.SendCoinsFromModuleToAccount // <--------
        (ctx, types.ModuleName, withdrawAddr, finalRewards)
        if err != nil {
            return nil, err
        }
    }

    ...

    return finalRewards, nil
}
```

There is another attack vector: if the malicious hook is triggered inside **BeginBlocker** or **EndBlocker**, it can panic and halt the entire chain. The call chain is:

```
BeginBlock
    x/slashing BeginBlocker
        HandleValidatorSignature
            SlashWithInfractionReason
                Slash
                    SlashRedelegation
                        Unbond
                            BeforeDelegationSharesModified
                                withdrawDelegationRewards
                                    SendCoinsFromModuleToAccount
                                        error
```

If a validator misbehaves (e.g., double-signs or goes offline), the slashing module’s BeginBlocker calls `HandleValidatorSignature`:

```go
// BeginBlocker check for infraction evidence or downtime of validators
// on every begin block
func BeginBlocker(ctx context.Context, k keeper.Keeper) error {
    ...
    for _, voteInfo := range sdkCtx.VoteInfos() {
        err := k.HandleValidatorSignature // <-------
        (ctx, voteInfo.Validator.Address, voteInfo.Validator.Power, comet.BlockIDFlag(voteInfo.BlockIdFlag))
        if err != nil {
            return err
        }
    }
    return nil
}
```

`HandleValidatorSignature` eventually calls `Slash`, which iterates over any redelegations and invokes `SlashRedelegation`:

```go
func (k Keeper) Slash(ctx context.Context, consAddr sdk.ConsAddress, infractionHeight, power int64, slashFactor math.LegacyDec) (math.Int, error) {
    ...
        redelegations, err := k.GetRedelegationsFromSrcValidator(ctx, operatorAddress)
        ...
        for _, redelegation := range redelegations {
            amountSlashed, err := k.SlashRedelegation // <---------
            (ctx, validator, redelegation, infractionHeight, slashFactor)
            ...
        }
    ...
}
```

The remaining path—`Unbond → BeforeDelegationSharesModified → withdrawDelegationRewards → SendCoinsFromModuleToAccount → error`—is identical to the first attack path.

So, once again, the attacker:

1. Sends the malicious denom to the validator via `MsgDepositValidatorRewardsPool`, placing it in pending rewards.
2. Uses `MsgBeginRedelegate` to move stake, ensuring the denom appears in redelegations.
3. Calls `MsgSetBeforeSendHook` with an invalid hook.

When **BeginBlocker** eventually triggers the hook, it errors and the chain stops.

## Recommendation

Restrict `MsgSetBeforeSendHook` so that **only addresses from a vetted whitelist** (or contracts that pass on-chain validation) can be registered as hooks.