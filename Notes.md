Summary
I reviewed the sources in src/ and found multiple high‑risk memory and API misuse issues that can readily cause core dumps, particularly under high load (more concurrency and larger packet volumes). The most critical ones are incorrect libuv callback signatures, severe bugs in the custom arena allocator, and a broken dynamic array implementation. Any one of these can crash; together they make crashes very likely when stressed.
Below are the concrete findings, with file/line references and why they can crash, followed by immediate mitigations and fix guidance.
Critical crash vectors
•
Wrong libuv callback signatures (stack corruption)
◦
File: src/collector.c
▪
void *after_work_cb(uv_work_t *req, int status) at lines ~297–306 — should be void after_work_cb(uv_work_t *req, int status).
▪
work_cb is of type uv_work_cb, but you assign functions like parse_v9 that are declared void *parse_v9(uv_work_t *req) (see src/netflow_v9.c:19). uv_queue_work expects void (*)(uv_work_t*). Returning the wrong type and using the wrong signature is undefined behavior and can corrupt the stack/ABI on callback invocation/completion. Under high load this will manifest as sporadic crashes.
•
Arena allocator arithmetic/logic bugs (heap corruption)
◦
File: src/arena.c
▪
overhead handling:
▪
int overhead = sizeof(arena_chunk_t); but later capacity check uses sizeof(overhead) (line ~81). sizeof(overhead) is 4/8, not the size of arena_chunk_t. This allows allocating past the end of the arena because the guard underestimates required bytes.
▪
Miscomputed chunk->end:
▪
chunk->end = (size_t *) chunk + chunk->size; (lines ~141, 156). Pointer arithmetic on size_t* scales by sizeof(size_t), not bytes; this sets an invalid end pointer and can break traversal or bounds checks.
▪
Inconsistent clearing:
▪
memset(address, 0, padding + bytes); clears user data but not the arena_chunk_t header placed at address. Headers may contain garbage leading to inconsistent occupied/free/size/next state.
▪
Free list reuse loop assumes arena->first_chunk non‑NULL and walks chunk = chunk->next until NULL, but the initial pointer arithmetic stores arena->first_chunk = address; where address is a data pointer, then chunk->data_address = address + overhead; (lines ~130–137). The list nodes themselves are not clearly separated from payload and can overlap due to the above calculation mistakes.
▪
In arena_free (lines ~262–284):
▪
The loop while (chunk->next != NULL) { if (chunk->data_address == address) break; chunk = chunk->next; } fails to check the last node (when next == NULL). If no match is found, it still proceeds to mark the last chunk as freed (chunk->occupied = 0;), freeing the wrong block and corrupting allocator state.
▪
Overall, multiple concurrency issues are mitigated by uv_mutex_lock, but the logical errors above are sufficient to cause corruption under load.
•
Dynamic array implementation corrupts memory immediately
◦
File: src/dyn_array.c
▪
dyn_array_create allocates arr = arena_alloc(arena, cap*elem_size); (line 19) but treats arr as a dyn_array_t* struct and writes arr->cap, arr->len (lines 23–25). This overwrites the start of the supposed element buffer with metadata fields, corrupting memory. It should allocate a dyn_array_t object plus a separate data buffer, or store data pointer inside.
▪
dyn_array_push/pop use arr->data but that pointer is never initialized in dyn_array_create.
▪
dyn_array_push computes destination with arr->data + arr->len * sizeof(*data) where data is void* — sizeof(*data) is ill‑formed/undefined and not the element size. This will write to incorrect addresses.
▪
Any call to dyn_array_create/push under load will corrupt the arena and lead to crashes. Note: collector_start calls dyn_array_create(...) and ignores the return, but the erroneous writes still occur.
•
Double destroy and inconsistent shutdown
◦
File: src/collector.c
▪
In the success path at lines ~278–283: arena_destroy(arena_collector); ... arena_destroy(arena_collector); — double destroy of the same arena pointer. If this path is taken more than once or if memory is re‑used, double free/invalid free can occur.
•
Potential buffer lifecycle mistakes across threads
◦
File: src/collector.c
▪
alloc_cb allocates packet buffers from arena_udp_handle and sets them in buf->base; udp_handle passes buf->base to worker via func_args->data; after_work_cb frees it. That pattern is fine in principle. But on early exits (e.g., unsupported version) you jump to udp_handle_free_and_return and free the buffer — OK. However, any mismatch in parse callback signature or early uv_queue_work failure will leak or double-free (compounded by arena bugs above).
•
Use of uv_default_loop() for multiple loop variables
◦
File: src/collector.c, lines ~239–242
▪
loop_timer_rss, loop_timer_snmp, loop_udp, loop_pool all set to uv_default_loop(). This is legal, but confusing. uv_queue_work(loop_pool, ...) queues on the same loop used for UDP I/O. Under high load, worker completion callbacks and I/O all share a single loop, which can lead to starvation and timing‑sensitive races. Not a direct crash cause, but it exacerbates the above issues.
•
HashMap concurrency and bounds
◦
File: src/hashmap.c
▪
The hashmap implementation is not obviously thread‑safe (no internal locks). In netflow_v9.c you may read/update templates from different work items (depending on how many work items run concurrently on the same loop). If accessed concurrently without external synchronization, the template store can be corrupted.
•
NetFlow v9 parsing has extensive pointer arithmetic and assumes templates are well‑formed
◦
File: src/netflow_v9.c
▪
There are checks (e.g., header count bounds, flowset length vs total packet) — good. But the code copies template sections using sizes derived from field_count and raw pointer offsets (e.g., lines ~152–154). Any misparsed length combined with the allocator’s corruption increases the crash likelihood.
Why it tends to crash under high load
•
More packets → more allocations/frees on the buggy arena → faster heap metadata corruption.
•
Concurrent work items hit the allocator’s flawed free‑list traversal and miscalculated end pointers more often.
•
The incorrect libuv callback signatures get invoked more frequently, so ABI/stack misuse triggers sooner.
•
The dyn_array_create call in startup already corrupts memory; under load the damage grows as more code touches the corrupted region.
Immediate actions to confirm and mitigate
•
Build with sanitizers (Debug profile already enables ASan in your CMakeLists.txt)
◦
Run the app with traffic replay; AddressSanitizer should report the exact sites of invalid accesses. Consider also enabling UndefinedBehaviorSanitizer: add -fsanitize=undefined to C and C++ flags in Debug.
•
Fix libuv callback signatures first (highest ROI)
◦
Change all work and after‑work callbacks to void signatures:
▪
void parse_v9(uv_work_t *req); and similar for v5/ipfix.
▪
void after_work_cb(uv_work_t* req, int status);
•
Disable/avoid dyn_array until fixed
◦
Remove calls to dyn_array_create or fix its implementation before using it. Current code corrupts memory at startup.
•
Fix arena allocator logic
◦
Use size_t overhead = sizeof(arena_chunk_t); and consistently add/subtract overhead (not sizeof(overhead)).
◦
Compute end pointers in bytes: chunk->end = (char*)chunk + chunk->size; and for the user data end, likely chunk->data_end = (char*)chunk->data_address + chunk->size; if needed.
◦
Store the arena_chunk_t header at a distinct location: set the list node pointer to the header, and set data_address = (char*)header + sizeof(arena_chunk_t). Right now arena->first_chunk = address; where address is the data start + header? The math is muddled; clarify and test.
◦
In arena_free, traverse and check the last node; if not found, do not free anything. Add assertions.
◦
Consider temporarily replacing the custom arena with malloc/free in Debug to isolate other issues.
•
One loop and thread pool
◦
If you intend to use a libuv thread pool, you usually don’t need multiple loop objects. Keep a single uv_default_loop() for I/O and timers and rely on uv_queue_work’s internal thread pool. Alternatively, create separate loops in separate threads explicitly. This won’t fix crashes but simplifies debugging.
•
Harden NetFlow parsing
◦
Before using any len/field_count, validate that computed slice ranges (flowset_base + offset + size) stay within args->len. Fail fast on inconsistencies.
Concrete to‑do list (priority order)
1)
Correct all libuv callback signatures to void.
2)
Remove or fix dyn_array usage; ensure dyn_array_t contains metadata and that arr->data is separately allocated/initialized and indexed with the configured elem_size.
3)
Repair the arena allocator:
◦
Consistent header placement/size accounting.
◦
Proper list traversal and free logic.
◦
Correct byte arithmetic.
◦
Add assertions and unit tests under stress.
4)
Eliminate double arena_destroy and audit all destroy paths.
5)
If templates hashmap is accessed across work items concurrently, protect it with a mutex or per‑exporter locks.
6)
Re‑run with ASan/UBSan and fix remaining parsing bounds issues reported.
Extra runtime diagnostics
•
Keep the existing RSS timer, but lower log volume in core paths; excessive fprintf can mask races.
•
Enable core dumps and symbolization: ulimit -c unlimited; ensure binaries keep debug symbols (-g, already enabled in Debug); use gdb or lldb to inspect the backtrace.
If you want, I can propose patches for the callback signatures and the most critical allocator mistakes first, then iterate with sanitizer results.