## Description

Decode BERT data from dmesg to give you a possible reason about why your server crashed or what possibly happened, at least a tiny bit more human readable, and match it against known bugs (at least those I encountered), might not be 100% accurate.
Some bank may be badly decoded (CS_V2 and LS_V2), I'm no expert at reading developper manuals.

## Usage:
```
python3 is-it-cpu-bug-or-solar-flares-or-badluck.py my_file
```

## Example:

```
BERT: Error records from previous boot:
[Hardware Error]: event severity: fatal
[Hardware Error]:  Error 0, type: fatal
[Hardware Error]:   section_type: IA32/X64 processor error
[Hardware Error]:   Local APIC_ID: 0x3c
[Hardware Error]:   CPUID Info:
[Hardware Error]:   00000000: 00a00f11 00000000 3c400800 00000000
[Hardware Error]:   00000010: 76fa320b 00000000 178bfbff 00000000
[Hardware Error]:   00000020: 00000000 00000000 00000000 00000000
[Hardware Error]:   Error Information Structure 0:
[Hardware Error]:    Error Structure Type: cache error
[Hardware Error]:    Check Information: 0x00000000060200ff
[Hardware Error]:     Transaction Type: 2, Generic
[Hardware Error]:     Operation: 0, generic error
[Hardware Error]:     Level: 0
[Hardware Error]:     Processor Context Corrupt: true
[Hardware Error]:     Uncorrected: true
[Hardware Error]:     Precise IP: false
[Hardware Error]:     Restartable IP: false
[Hardware Error]:     Overflow: false
[Hardware Error]:   Context Information Structure 0:
[Hardware Error]:    Register Context Type: MSR Registers (Machine Check and other MSRs)
[Hardware Error]:    Register Array Size: 0x0080
[Hardware Error]:    MSR Address: 0xc0002030
[Hardware Error]:    Register Array:
[Hardware Error]:    00000000: 0000000000000000 b2a0000000090108
[Hardware Error]:    00000010: 0000000000000000 d010000000000000
[Hardware Error]:    00000020: 00000003000001f9 000300b00000003c
[Hardware Error]:    00000030: 000000004d000001 0000000000000000
[Hardware Error]:    00000040: 0000000000000000 0000000000000000
[Hardware Error]:    00000050: 0000000000000000 0000000000000000
[Hardware Error]:    00000060: 0000000000000000 0000000000000000
[Hardware Error]:    00000070: 0000000000000000 0000000000000000
BERT: Total records found: 1
PM:   Magic number: 1:816:184
```

```
python3 is-it-cpu-bug-or-solar-flares-or-badluck.py my_bert
APIC 0x3c   bank 3 -> DE
MCA_STATUS_DE                  0xb2a0000000090108
MCA_STATUS_DE[ExtErrorCode]    0x09 (9)   HwAssertMca - Hardware Assertion MCA Error
MCA_STATUS_DE[ErrorCode]       0x0108   memory hierarchy (cache) error, generic error, generic, L0
MCA_IPID_DE                    0x000300b00000003c   HwId=0x0b0 McaType=0x0003
MCA_SYND_DE                    0x000000004d000001
MCA_SYND_DE[ErrorInformation]  0x0001 (1)
Synd[0]                        1
flags                          Val UC En PCC TCC SyndV
verdict:                       HPE/Dell criterion: Bank 0x03 and Synd[0]=1 -> AmdIcConfigDisableITBypass
```
Probably this damn bug -> https://www.dell.com/support/kbdoc/en-us/000304911/dell-poweredge

Inspired by: https://github.com/DimitriFourny/MCE-Ryzen-Decoder
