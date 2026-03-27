Batch entrypoints for STARK-based signature verification.<br /><br />This module is intended for throughput benchmarking in Miden VM by verifying<br />a power-of-two number of signatures in one program run.<br /><br />It exposes two batching modes:<br />1. `verify_*`: each signature provides its own `(pk, msg)` on the operand stack;<br />proof data is read from the advice stack.<br />2. `verify_same_msg_*`: a single shared `msg` is loaded once from the operand<br />stack, then each signer provides only `pk` on the operand stack; proof data<br />is read from the advice stack.<br />


## miden::core::sig::batch
| Procedure | Description |
| ----------- | ------------- |
| verify_1 | Verify one signature (independent msg per signature).<br /><br />Inputs:<br />Operand stack: [pk0(4), msg0(4)]<br />Advice stack:  [proof0...]<br /> |
| verify_2 | Verify two signatures (independent msg per signature).<br /><br />Inputs:<br />Operand stack: [pk0(4), msg0(4), pk1(4), msg1(4)] (top verified first)<br />Advice stack:  [proof0..., proof1...]<br /> |
| verify_4 | Verify four signatures (independent msg per signature).<br /> |
| verify_8 | Verify eight signatures (independent msg per signature).<br /> |
| verify_16 | Verify sixteen signatures (independent msg per signature).<br /> |
| verify_32 | Verify thirty-two signatures (independent msg per signature).<br /> |
| verify_same_msg_1 | Verify one signature over a shared message.<br /><br />Inputs:<br />Operand stack: [msg(4), pk0(4)]<br />Advice stack:  [proof0...]<br /> |
| verify_same_msg_2 | Verify two signatures over a shared message.<br /><br />Inputs:<br />Operand stack: [msg(4), pk0(4), pk1(4)]<br />After storing msg, pk0 is on top and verified first; pk1 is verified second.<br />Advice stack:  [proof0..., proof1...]<br /> |
| verify_same_msg_4 | Verify four signatures over a shared message.<br /> |
| verify_same_msg_8 | Verify eight signatures over a shared message.<br /> |
| verify_same_msg_16 | Verify sixteen signatures over a shared message.<br /> |
| verify_same_msg_32 | Verify thirty-two signatures over a shared message.<br /> |
