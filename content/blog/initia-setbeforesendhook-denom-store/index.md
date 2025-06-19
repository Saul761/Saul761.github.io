---
title: "Initia: SetBeforeSendHook Can Never Delete the Store for Denom Prefix"
date: "2025-06-19"
description: "Initia: SetBeforeSendHook Can Never Delete the Store for Denom Prefix"
tags: ["Cosmos", "Initia", "Audit Competition"]
---

# Initia: SetBeforeSendHook Can Never Delete the Store for Denom Prefix

In Initia’s `x/tokenfactory` module, a token administrator can use `MsgSetBeforeSendHook` to attach a **BeforeSend** hook (a CosmWasm contract address) to a custom denom. On every transfer of that denom, the chain first executes the hook via `sudo` and then decides whether to allow the transfer.

The message is also supposed to let the admin **remove** the hook: passing an **empty `cosmwasmAddress` string** should delete the stored hook.

```go
func (k Keeper) setBeforeSendHook(ctx context.Context, denom, cosmwasmAddress string) error {
    // verify that denom is a tokenfactory denom
    _, _, err := types.DeconstructDenom(k.ac, denom)
    if err != nil { return err }

    // delete the store for denom prefix when the address is empty
    if cosmwasmAddress == "" {           // <—
        return k.DenomHookAddr.Remove(ctx, denom)
    }

    _, err = k.ac.StringToBytes(cosmwasmAddress)
    if err != nil { return err }

    return k.DenomHookAddr.Set(ctx, denom, cosmwasmAddress)
}
```

**Problem:** Before the keeper logic runs, the message is validated. If `cosmwasmAddress` is empty, validation fails, so the request never reaches the deletion branch.

```go
func (m MsgSetBeforeSendHook) Validate(accAddrCodec address.Codec) error {
    if addr, err := accAddrCodec.StringToBytes(m.Sender); err != nil {
        return err
    } else if len(addr) == 0 {           // <—
        return ErrEmptySender
    }
    ...
    return nil
}
```

Because of this redundant check, `SetBeforeSendHook` can **never** “delete the store for denom prefix,” i.e., a hook once set can’t be removed.

**Recommendation**

Remove the over-strict validation (or explicitly allow an empty `cosmwasmAddress`) so that admins can clear a denom’s BeforeSend hook as intended.