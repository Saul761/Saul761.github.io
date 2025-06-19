---
title: "Mezo: memEventBus Read/Write Race Causes RPC DoS"
date: "2025-06-19"
description: "Mezo: memEventBus Read/Write Race Causes RPC DoS"
tags: ["Cosmos", "Mezo", "Audit Competition", "DOS"]
---

## Vulnerability Background

The **`rpc/ethereum/pubsub`** module in Mezo nodes offers WebSocket-style subscriptions similar to Geth, streaming new-block headers, logs, and other on-chain events to wallets and backend services in real time.

The core component, **`memEventBus`,** maintains subscription state via three nested maps:

```go
type memEventBus struct {
    topics          map[string]<-chan coretypes.ResultEvent                 // event “bus”
    topicsMux       *sync.RWMutex                                           // guards topics
    subscribers     map[string]map[uint64]chan<- coretypes.ResultEvent      // event → sub-ID → channel
    subscribersMux  *sync.RWMutex                                           // guards subscribers
    currentUniqueID uint64                                                 // auto-increment sub ID
}
```

- **First-level key (`string`)** – event name: `"newHeads"`, `"logs"`, `"newPendingTransactions"`, etc.
- **Second-level key (`uint64`)** – subscription ID, incremented on each `eth_subscribe`.
- **Value (`chan ResultEvent`)** – a dedicated channel; the publisher writes, the RPC layer reads.

### Minimal publish loop

1. **Register topic**
    
    Consensus creates `logsChan` → `AddTopic("logs", logsChan)` → `topics["logs"] = logsChan`.
    
2. **Subscribe (`eth_subscribe`)**
    
    RPC parses the request, allocates an **unbuffered** `ch`, then:
    
    ```go
    ch := make(chan coretypes.ResultEvent)
    Lock()
    subscribers["logs"][id] = ch
    Unlock()
    ```
    
3. **Publish** – consensus thread writes to `srcChan`; `publishAllSubscribers` forwards:
    
    ```go
    func publishAllSubscribers(name, msg) {
        RLock()
        subs := subscribers[name]
        RUnlock()                    // <— flaw: lock released too early
        for _, ch := range subs {
            select { case ch <- msg : default }
        }
    }
    ```
    
4. **Push** – RPC goroutine reads from `ch`, JSON-encodes, and writes via WebSocket.
5. **Unsubscribe (`eth_unsubscribe`)**
    
    ```go
    Lock()
    close(ch)
    delete(subscribers["logs"], id)
    Unlock()
    ```
    
6. **Concurrency guarantees**
    - Publishers acquire **RLock**; writers are blocked while a read lock is held.
    - Subscriptions/unsubscriptions acquire **Lock** (exclusive write).
    - Channels plus `select default` prevent slow clients from blocking publishers.

## Vulnerability Description

In **`publishAllSubscribers`** the read lock is released immediately after taking a reference to the shared map:

```go
func (m *memEventBus) publishAllSubscribers(name string, msg coretypes.ResultEvent) {
    m.subscribersMux.RLock()              // ① acquire read lock
    subs := m.subscribers[name]           // ② get map reference
    m.subscribersMux.RUnlock()            // ③ release lock too early

    for _, ch := range subs {             // ④ iteration now unprotected
        select {
        case ch <- msg:
        default:
        }
    }
}
```

- After step ③ the code continues to **iterate over `subs` without any lock**.
- If, during that window, another goroutine executes `Subscribe` or `Unsubscribe` and acquires the write lock to add/remove an element in the very same map, the Go runtime detects “concurrent map iteration and map write” and triggers a **fatal `panic`**.

### Trigger paths

- **Read side** – the goroutine spawned in `AddTopic` calls `publishAllSubscribers` on every block/log.
- **Write side** – any external client spamming `eth_subscribe` / `eth_unsubscribe`.

A malicious user can simply fire rapid subscribe/unsubscribe requests while blocks are produced, reliably hitting the race and crashing the node.

## Recommendation

Hold the read lock for the entire iteration so writers stay blocked until traversal finishes:

```go
func (m *memEventBus) publishAllSubscribers(name string, msg coretypes.ResultEvent) {
    m.subscribersMux.RLock()              // acquire read lock for full scope
    defer m.subscribersMux.RUnlock()      // release on function exit

    subs := m.subscribers[name]           // safe access
    for _, ch := range subs {
        select {
        case ch <- msg:
        default:
        }
    }
}
```