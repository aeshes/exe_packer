This is PE-packer for protestion from signature and bihaviour analysis.

#Stub
Runtime decriptor. Decrypts payload in memory and runs it restartig its own process (RunPE method, process injecting).

#Builder
Covers payload with protection. Usage: builder.exe payload.exe.
When stub and builder are updated, builder needs to be recompiled using new stub.h header. This header contains hex data of stub.exe. Use stub2header.bat to make new stub.h header.
