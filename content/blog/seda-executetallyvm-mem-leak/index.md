---
title: "Seda Chain: Memory Leak in ExecuteTallyVm Eventually Crashes Nodes"
date: "2025-06-19"
description: "Seda Chain: Memory Leak in ExecuteTallyVm Eventually Crashes Nodes"
tags: ["Cosmos", "Nibiru", "Audit Competition", "DOS"]
---

## Background

- **SEDA Chain** – a Cosmos-SDK-based proof-of-stake chain that handles settlement and data attestation for bridges, oracles, and “chain-abstraction” use-cases. Nodes must run custom verification logic continuously, 24 × 7.
- **Tally VM** – an internal sandbox that lets SEDA nodes run verification / tally byte-code safely between Go and C.
- **`ExecuteTallyVm`** – a Go-level wrapper that passes byte-code, arguments, and environment variables down to the C function `execute_tally_vm` and returns the result. Each invocation converts `LogDir` into a C string `configDirC` so the VM can write logs.

In a long-running, highly concurrent blockchain process, every unreleased CGO resource accumulates linearly with call volume and threatens chain availability.

## Vulnerability

In `tallyvm.go`, `configDirC := C.CString(LogDir)` allocates memory on the C heap, but there is **no matching `C.free` call**. The final `C.free_ffi_vm_result` only frees the VM result, not `configDirC`.

```go
func ExecuteTallyVm(bytes []byte, args []string, envs map[string]string) VmResult {
    // convert config dir to C string
    configDirC := C.CString(LogDir)  // <-------

    ...
    result := C.execute_tally_vm(
        configDirC,
        bytesPtr, C.uintptr_t(len(bytes)),
        argsPtr, C.uintptr_t(len(args)),
        keysPtr, valuesPtr, C.uintptr_t(len(envs)),
    )
    exitMessage := C.GoString(result.exit_info.exit_message)
    exitCode := int(result.exit_info.exit_code)

    defer C.free_ffi_vm_result(&result)  // <-------

    ...
}
```

Each call therefore leaks a chunk of memory. Under the chain’s high-frequency workload, the process’s resident set size grows steadily until the node runs out of memory and crashes, creating a denial-of-service vector.

## Mitigation

After calling `C.CString(LogDir)` in `ExecuteTallyVm`, always free the allocation:

```go
configDirC := C.CString(LogDir)
defer C.free(unsafe.Pointer(configDirC))
```

Placing the `defer` immediately after the allocation ensures the memory is released on every code path.