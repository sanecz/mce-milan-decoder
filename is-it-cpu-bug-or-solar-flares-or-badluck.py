import sys
import re
from tabulate import tabulate


HWERR_REGEX = re.compile(r"(?<=\[Hardware Error\]:)\s+(?P<line>.*)")
APIC_REGEX = re.compile(r"(?<=Local APIC_ID: )(?P<apic>0x[0-9A-Fa-f]+)")
MSR_REGEX = re.compile(r"MSR Address:\s*(?P<msr>0x[0-9A-Fa-f]+)")
ROW_REGEX = re.compile(r"^(?P<off>[0-9a-f]{8}):\s+(?P<vals>(?:[0-9a-f]{16}\s*)+)$")
MSR_CTX = "Register Context Type: MSR Registers (Machine Check and other MSRs)"

SMCA = {
    (0xB0, 0x00): "LS",   (0xB0, 0x10): "LS_V2",
    (0xB0, 0x01): "IF",   (0xB0, 0x02): "L2",
    (0xB0, 0x03): "DE",   (0xB0, 0x05): "EX",
    (0xB0, 0x06): "FP",   (0xB0, 0x07): "L3",
    (0x2E, 0x00): "CS",   (0x2E, 0x01): "PIE",  (0x2E, 0x02): "CS_V2",
    (0x96, 0x00): "UMC",  (0x96, 0x01): "UMC_V2",
    (0x05, 0x00): "PB",
}

FLAGS = ("uc", "pcc", "tcc", "deferred", "poison", "addrv")

_ = None

LS = [
    ("DC_DATA_VICTIM", 0, 0, 0, _, 0, 1,
     "An ECC error was detected in the data cache data array. The error was "
     "detected on a data cache read by a probe or victimization of a dirty line."),
    ("DC_DATA_LOAD", _, 0, _, 0, _, 1,
     "An ECC error or poison consumption was detected on a data cache read by "
     "a load. MCA_SYND_LS[0]=0 for a data cache ECC error, and "
     "MCA_SYND_LS[0]=1 for poison data originating from outside the core."),
    ("DC_DATA_RMW", 0, 0, 0, _, 0, 1,
     "An ECC error was detected in the data cache data array. This error was "
     "detected on a data cache read-modify-write by a store."),
    ("DC_TAG_VICTIM", _, _, _, _, 0, 0,
     "An ECC error was detected in the data cache tag array, or a mismatch was "
     "detected in the data cache tag meta-data poison bit. The error was "
     "detected on a tag read by a probe or victimization."),
    ("DC_TAG_LOAD", _, _, _, _, 0, 0,
     "An ECC error was detected in the data cache tag array, or a mismatch was "
     "detected in the data cache tag meta-data poison bit. The error was "
     "detected on a tag read by a load."),
    ("DC_TAG_STORE", _, _, _, _, 0, 0,
     "An ECC error was detected in the data cache tag array, or a mismatch was "
     "detected in the data cache tag meta-data poison bit. The error was "
     "detected on a tag read by a store."),
    ("DC_DATA_LOAD_2", 1, 1, 1, 0, 0, 1,
     "An ECC error was detected in the data cache data array. This error was "
     "detected on a load."),
    ("DC_DATA_RMW_2", _, _, _, 0, 0, 0,
     "An ECC error was detected in the data cache data array. This error was "
     "detected on a read-modify-write by a store."),
    ("L1DTLB", 0, 0, 0, 0, 0, 0,
     "A parity error was detected in a Level 1 Translation Lookaside Buffer "
     "(L1 TLB) entry."),
    ("L2DTLB", 0, 0, 0, 0, 0, 1,
     "A parity error was detected in a Level 2 Translation Lookaside Buffer "
     "(L2 TLB) entry."),
    ("PWC", 0, 0, 0, 0, 0, 1,
     "A parity error was detected in a Page Walk Cache (PWC) entry."),
    ("STQ", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in a Store Queue (STQ) entry."),
    ("LDQ", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in a Load Queue (LDQ) entry."),
    ("MAB", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in a Miss Address Buffer (MAB) entry."),
    ("SCB_STATE", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in the State field of a Store Coalescing "
     "Buffer (SCB) entry."),
    ("SCB_ADDR", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in the Address field of a Store Coalescing "
     "Buffer (SCB) entry."),
    ("SCB_DATA", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in the Data field of a Store Coalescing "
     "Buffer (SCB) entry."),
    ("WCB", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in a Write Coalescing buffer (WCB) entry."),
    ("SCB_POISON", 0, 0, 0, 1, 0, 0,
     "A poisoned line was detected in a Store Coalescing Buffer (SCB) entry."),
    ("SystemReadDataErrorLoad", 1, 0, 1, 0, 0, 1,
     "A SystemReadDataError error was reported for read data originating from "
     "outside the core. The error was detected by a load."),
    ("SystemReadDataErrorScb", 1, 1, 1, 0, 0, 1,
     "A SystemReadDataError error was reported for read data originating from "
     "outside the core. The error was detected by a Store Coalescing Buffer "
     "(SCB) read-modify-write."),
    ("SystemReadDataErrorWcb", 1, 1, 1, 0, 0, 0,
     "A SystemReadDataError error was reported for read data originating from "
     "outside the core. The error was detected by a Write Coalescing Buffer "
     "(WCB) read-modify-write."),
    ("HWA", 1, 1, 1, 0, 0, 0,
     "A Hardware Assertion (HWA) error was reported."),
    ("STORE_DATA_OTHER", 1, 1, 1, 0, 0, 0,
     "A parity error was detected in a Store-to-Load Forwarding (STLF) data "
     "entry. The error was detected on a store or on a load which consumes "
     "STLF data."),
]

IF = [
    ("OcUtagParity", 1, 1, 1, 0, 0, 0,
     "Op Cache Microtag Parity Error. Parity errors on PA and other relevant "
     "uTag fields are reported, independent of any utag probing. The parity "
     "error way and index are logged."),
    ("TagMultiHit", 0, 0, 0, 0, 0, 1, "IC Full Tag Multi-hit Error."),
    ("TagParity", 0, 0, 0, 0, 0, 1, "IC Full Tag Parity Error."),
    ("DataParity", 0, 0, 0, 0, 0, 1, "IC Data Array Parity Error."),
    ("DqParity", 1, 1, 1, 0, 0, 0, "PRQ Parity Error."),
    ("RSVD_5", 1, 1, 1, 0, 0, 0, "Reserved. Will never trigger."),
    ("L1ItlbParity", 0, 0, 0, 0, 0, 1, "L1-TLB Parity Error."),
    ("L2ItlbParity", 0, 0, 0, 0, 0, 1, "L2-TLB Parity Error."),
    ("RSVD_8", 1, 1, 1, 0, 0, 0, "Reserved. Will never trigger."),
    ("IcUtagParity", 0, 0, 0, 0, 0, 0, "Ic MicroTag Parity Error."),
    ("L1BtbMultiHit", 0, 0, 0, 0, 0, 0, "BP L1-BTB Multi-Hit Error."),
    ("L2BtbMultiHit", 0, 0, 0, 0, 0, 0, "BP L2-BTB Multi-Hit Error."),
    ("L2RespPoison", 1, 0, 1, 0, 1, 1,
     "L2 Cache Response Poison Error. Error is the result of consuming poison "
     "data."),
    ("SystemReadDataError", 1, 0, 1, 0, 0, 1, "L2 Cache Error Response."),
    ("HwAssert", 1, 1, 1, 0, 0, 0, "Hardware Assertion Error."),
    ("L1TlbMultiHit", 0, 0, 0, 0, 0, 1, "L1-TLB Multi-Hit."),
    ("L2TlbMultiHit", 0, 0, 0, 0, 0, 1, "L2-TLB Multi-Hit."),
    ("BsrParity", 1, 1, 1, 0, 0, 0, "BSR Parity Error."),
    ("CtMceError", 1, 1, 1, 0, 0, 0, "CT MCE."),
]

L2 = [
    ("MultiHit", 1, 1, 1, 0, 0, 1, "L2M Tag Multiple-Way-Hit error."),
    ("Tag", _, _, _, 0, 0, 1, "L2M Tag or State Array ECC Error."),
    ("Data", _, _, _, _, 0, 1, "L2M Data Array ECC Error."),
    ("Hwa", 1, 1, 1, 0, 0, 1, "Hardware Assert Error."),
]

DE = [
    ("OcTag", _, _, _, _, 0, 0, "Micro-op cache TAG Array parity error"),
    ("OcDat", _, _, _, _, 0, 0, "Micro-op cache DATA Array parity error"),
    ("Ibq", _, _, _, _, 0, 0, "IBB Register File parity error"),
    ("UopQ", _, _, _, _, 0, 0, "Micro-op Queue parity error"),
    ("Idq", _, _, _, _, 0, 0, "Instruction dispatch queue parity error"),
    ("Faq", _, _, _, _, 0, 0, "Fetch address FIFO parity error"),
    ("UcDat", _, _, _, _, 0, 0, "Patch RAM data parity error"),
    ("UcSeq", _, _, _, _, 0, 0, "Patch RAM sequencer parity error"),
    ("OCBQ", _, _, _, _, 0, 0, "Micro-op buffer parity error"),
    ("HwAssertMca", _, _, _, _, 0, 0, "Hardware Assertion MCA Error"),
]

EX = [
    ("WDT", 1, 1, 1, 0, 0, 1, "Watchdog Timeout."),
    ("PRF", 1, 1, 1, 0, 0, 0, "Physical register file (PRF) parity error."),
    ("FRF", 1, 1, 1, 0, 0, 0, "Flag register file (FRF) parity error."),
    ("IDRF", 1, 1, 1, 0, 0, 0,
     "Immediate displacement register file parity error."),
    ("PLDAG", 1, 1, 1, 0, 0, 0, "Address generator payload parity error."),
    ("PLDAL", 1, 1, 1, 0, 0, 0, "EX payload parity error."),
    ("CHKPTQ", 1, 1, 1, 0, 0, 0,
     "Checkpoint Queue (AKA Map_DispQ) parity error."),
    ("RETDISP", 1, 1, 1, 0, 0, 0, "Retire Dispatch Queue parity error."),
    ("STATQ", 1, 1, 1, 0, 0, 0, "Retire status queue parity error."),
    ("SQ", 1, 1, 1, 0, 0, 0, "Scheduler Queue parity error."),
    ("BBQ", 1, 1, 1, 0, 0, 0, "Branch Buffer Queue (BBQ) parity error."),
    ("HWA", 1, 1, 1, 0, 0, 0, "Hardware Assertion Error."),
    ("SPECMAP", 1, 1, 1, 0, 0, 0, "Spec Map parity error."),
    ("RETMAP", 1, 1, 1, 0, 0, 0, "Retire Map parity error."),
]

FP = [
    ("PRF", 1, 1, 1, 0, 0, 0, "Physical register file (PRF) parity error."),
    ("FL", 1, 1, 1, 0, 0, 0, "Freelist (FL) parity error."),
    ("SCH", 1, 1, 1, 0, 0, 0, "Schedule queue parity error."),
    ("NSQ", 1, 1, 1, 0, 0, 0, "NSQ parity error."),
    ("RQ", 1, 1, 1, 0, 0, 0, "Retire queue (RQ) parity error."),
    ("SRF", 1, 1, 1, 0, 0, 0, "Status register file (SRF) parity error."),
    ("HWA", 1, 1, 1, 0, 0, 0, "Hardware assertion."),
]

L3 = [
    ("ShadowTag", _, _, _, _, _, _, "Shadow Tag Macro ECC Error."),
    ("MultiHitShadowTag", _, _, _, _, _, _,
     "Shadow Tag Macro Multi-way-hit Error."),
    ("Tag", _, _, _, _, _, _, "L3M Tag ECC Error."),
    ("MultiHitTag", _, _, _, _, _, _, "L3M Tag Multi-way-hit Error."),
    ("DataArray", _, _, _, _, _, _, "L3M Data ECC Error."),
    ("SdpParity", _, _, _, _, _, _, "SDP Parity Error from XI."),
    ("XiVictimQueue", _, _, _, _, _, _, "L3 Victim Queue Parity Error."),
    ("Hwa", _, _, _, _, _, _, "L3 Hardware Assertion."),
]

CS = [
    ("FTI_ILL_REQ", 0, 0, 0, 1, 0, 1,
     "Illegal Request: An illegal request was received from the transport layer."),
    ("FTI_ADDR_VIOL", 0, 0, 0, 1, 0, 1,
     "Address Violation: An address violation was received from the transport "
     "layer."),
    ("FTI_SEC_VIOL", 0, 0, 0, 1, 0, 1,
     "Security Violation: A security violation was received from the transport "
     "layer."),
    ("FTI_ILL_RSP", 1, 1, 1, 0, 0, 0,
     "Illegal Response: An illegal response was received from the transport "
     "layer."),
    ("FTI_RSP_NO_MTCH", 1, 1, 1, 0, 0, 0,
     "Unexpected Response: A response was received from the transport layer "
     "which does not match any request."),
    ("FTI_PAR_ERR", 0, 0, 0, 1, 0, 1,
     "Request or Probe Parity Error: Parity error on incoming request or probe "
     "response data."),
    ("SDP_PAR_ERR", 0, 0, 0, 1, 0, 1,
     "Read Response Parity Error: Parity error on incoming read response data."),
    ("ATM_PAR_ERR", 0, 0, 0, 1, 0, 1,
     "Atomic Request Parity Error: Parity error on read of an atomic "
     "transaction."),
    ("SDP_RSP_NO_MTCH", 1, 1, 1, 0, 0, 0,
     "SDP read response had no match in the CS queue."),
    ("SPF_PRT_ERR", 1, 1, 1, 0, 0, 0,
     "Probe Filter Protocol Error: Indicates a Cache Coherence Issue."),
    ("SPF_ECC_ERR", 0, 0, 0, 0, 0, 1,
     "Probe Filter ECC Error: An ECC error occurred on a probe filter access."),
    ("SDP_UNEXP_RETRY", 1, 1, 1, 0, 0, 1,
     "SDP read response had an unexpected RETRY error."),
    ("CNTR_OVFL", 1, 1, 1, 0, 0, 0, "Counter overflow error."),
    ("CNTR_UNFL", 1, 1, 1, 0, 0, 0, "Counter underflow error."),
]

PIE = [
    ("HW_ASSERT", 1, 1, 1, 0, 0, 0,
     "Hardware Assert: A hardware assert was detected."),
    ("CSW", 0, 0, 0, 1, 0, 0,
     "Register security violation: A security violation was detected on an "
     "access to an internal PIE register."),
    ("GMI", _, _, _, 0, 0, 0,
     "Link Error: An error occurred on a GMI or xGMI link."),
    ("FTI_DAT_STAT", 1, 1, 1, 0, 0, 0,
     "Poison data consumption: Poison data was written to an internal PIE "
     "register."),
    ("DEF", 0, 0, 0, 1, 0, 0, "A deferred error was detected in the DF."),
]

UMC = [
    ("DramEccErr", _, _, _, _, 0, 1,
     "DRAM ECC error. An ECC error occurred on a DRAM read."),
    ("WriteDataPoisonErr", 1, 1, 1, 0, 0, 0,
     "Data poison error. The system tried to write poison data to DRAM and "
     "either DRAM does not support ECC or UMC_CH.EccCtrl.WrEccEn is cleared."),
    ("SdpParityErr", 1, 1, 1, 0, 0, 0,
     "SDP parity error. A parity error was detected on write data from the "
     "data fabric in the processor."),
    ("ApbErr", 1, 1, 1, 0, 0, 1,
     "Advanced peripheral bus error. An error occurred on the advanced "
     "peripheral bus."),
    ("AddressCommandParityErr", _, _, _, 0, 0, _,
     "Address/Command parity error. A parity error occurred on the DRAM "
     "address/command bus."),
    ("WriteDataCrcErr", _, _, _, 0, 0, 0,
     "Write data CRC error. A write data CRC error occurred on the DRAM data "
     "bus."),
    ("DcqSramEccErr", _, _, _, 0, 0, 0,
     "DCQ SRAM ECC error. An ECC error occured on a DCQ SRAM in the processor."),
    ("AesSramEccErr", _, _, _, 0, 0, 0,
     "AES SRAM ECC error. An ECC error occured on a AES SRAM in the processor."),
]

PB = [
    ("EccError", _, _, _, 0, 0, 0,
     "An ECC error in the Parameter Block RAM array."),
]

XEC_TABLES = {
    "LS": LS, "LS_V2": LS,
    "IF": IF, "L2": L2, "L3": L3, "DE": DE, "EX": EX, "FP": FP,
    "CS": CS, "CS_V2": CS, "PIE": PIE,
    "UMC": UMC, "UMC_V2": UMC, "PB": PB,
}


def lookup(unit, xec):
    table = XEC_TABLES.get(unit)
    if table is None or xec >= len(table):
        return None, None, None
    row = table[xec]
    return row[0], dict(zip(FLAGS, row[1:7])), row[7]


TT = {0b00: "instruction", 0b01: "data", 0b10: "generic"}

LL = {0b00: "L0", 0b01: "L1", 0b10: "L2", 0b11: "L3/generic"}

RRRR = {
    0b0000: "generic error", 0b0001: "generic read", 0b0010: "generic write",
    0b0011: "data read", 0b0100: "data write", 0b0101: "instruction fetch",
    0b0110: "prefetch", 0b0111: "eviction", 0b1000: "snoop",
}

PP = {0b00: "local processor originated request",
      0b01: "local processor responded to request",
      0b10: "local processor observed error as third party",
      0b11: "generic participation"}

II = {0b00: "memory access", 0b10: "IO access", 0b11: "other transaction"}


def decode_errorcode(code):
    if code & 0xFFF0 == 0x0010:
        parts = ["TLB error"]
        tt, ll = (code >> 2) & 3, code & 3
    elif code & 0xFF00 == 0x0100:
        parts = ["memory hierarchy (cache) error", RRRR.get((code >> 4) & 0xF, "?")]
        tt, ll = (code >> 2) & 3, code & 3
    elif code & 0xF800 == 0x0800:
        parts = ["bus/interconnect error",
                 PP.get((code >> 9) & 3, "?"),
                 "timeout" if (code >> 8) & 1 else "no timeout",
                 RRRR.get((code >> 4) & 0xF, "?"),
                 II.get((code >> 2) & 3, "?")]
        tt, ll = None, code & 3
    else:
        return "unknown encoding"
    if tt is not None:
        parts.append(TT.get(tt, "?"))
    parts.append(LL.get(ll, "?"))
    return ", ".join(parts)


class McaRecord:
    def __init__(self, msr_base, qwords, apic=None):
        self.msr_base = msr_base
        self.q = qwords
        self.apic = apic

    @property
    def bank_idx(self):
        return (self.msr_base - 0xC0002000) // 0x10

    @property
    def status(self): return self.q.get(1, 0)
    @property
    def addr(self): return self.q.get(2, 0)
    @property
    def misc0(self): return self.q.get(3, 0)
    @property
    def config(self): return self.q.get(4, 0)
    @property
    def ipid(self): return self.q.get(5, 0)
    @property
    def synd(self): return self.q.get(6, 0)

    @property
    def valid(self): return bool(self.status >> 63 & 1)
    @property
    def overflow(self): return bool(self.status >> 62 & 1)
    @property
    def uc(self): return bool(self.status >> 61 & 1)
    @property
    def enabled(self): return bool(self.status >> 60 & 1)
    @property
    def miscv(self): return bool(self.status >> 59 & 1)
    @property
    def addrv(self): return bool(self.status >> 58 & 1)
    @property
    def pcc(self): return bool(self.status >> 57 & 1)
    @property
    def tcc(self): return bool(self.status >> 55 & 1)
    @property
    def syndv(self): return bool(self.status >> 53 & 1)
    @property
    def deferred(self): return bool(self.status >> 44 & 1)
    @property
    def poison(self): return bool(self.status >> 43 & 1)

    @property
    def errorcodeext(self): return self.status >> 16 & 0x3F
    @property
    def errorcode(self): return self.status & 0xFFFF
    @property
    def errorinformation(self): return self.synd & 0xFFFF

    @property
    def unit(self):
        hi = self.ipid >> 32
        return SMCA.get((hi & 0xFFF, hi >> 16 & 0xFFFF), f"?({self.bank_idx})")

    @property
    def error_type(self):
        return lookup(self.unit, self.errorcodeext)[0]

    @property
    def expected_flags(self):
        return lookup(self.unit, self.errorcodeext)[1]

    @property
    def error_desc(self):
        return lookup(self.unit, self.errorcodeext)[2]

    def check_flags(self):
        problems = []
        if not self.valid:
            problems.append("MCA_STATUS[Val]=0: empty record, do not interpret")
            return problems
        acr = self.error_type
        if acr is None:
            table = XEC_TABLES.get(self.unit)
            n = len(table) if table else 0
            problems.append(
                f"ErrorCodeExt=0x{self.errorcodeext:02x} not in {self.unit} table"
                + (f" ({n} entries): stale table or wrong offset"
                   if n else ": no table for this unit"))
            return problems
        if acr.startswith("RSVD"):
            problems.append(
                f"{acr}: reserved bit, should never trigger -> suspect parsing")
        for name, want in self.expected_flags.items():
            if want is None:
                continue
            got = int(getattr(self, name))
            if got != want:
                problems.append(
                    f"{name.upper()}={got}, PPR expects {want} "
                    f"for {self.unit}/{acr}")
        return problems

    @property
    def coherent(self):
        return not self.check_flags()

    def known_issues(self):
        u, acr, ei = self.unit, self.error_type, self.errorinformation
        hits = []
        if u == "IF" and acr == "HwAssert":
            if ei == 0x25:
                hits.append("erratum 1415: Processor Undergoing C-State Change May Signal Unexpected Fatal IF MCA Error")
            elif ei in (0x22, 0x23, 0x2F, 0x30):
                hits.append("erratum 1407: Processor May Signal Unexpected Fatal IF MCA Error")
        elif u in ("LS", "LS_V2") and acr == "HWA":
            if self.synd == 0x5D00008E:
                hits.append("erratum 1433: Processor May Log Unexpected LS MCE Error")
            elif ei == 0x8E:
                hits.append("erratum 1450: Processor May Signal a Fatal LS MCA Error")
        elif u in ("CS", "CS_V2") and (self.errorcode >> 4 & 0xF) == 0b0101 \
                and acr in ("FTI_ILL_REQ", "FTI_ADDR_VIOL", "FTI_SEC_VIOL",
                            "FTI_ILL_RSP", "FTI_RSP_NO_MTCH", "SPF_PRT_ERR",
                            "SDP_RSP_NO_MTCH", "SDP_UNEXP_RETRY",
                            "CNTR_OVFL", "CNTR_UNFL"):
            hits.append("erratum 1225: ErrorCode RRRR field is bogus rely on ErrorCodeExt")
        elif u == "CS" and self.errorcodeext == 0x11 and self.synd == 0x5D000001:
            hits.append("spurious CS HW assert on DRAM UMCE, data poisoning disabled")
        elif u == "PIE" and acr == "HW_ASSERT" and self.synd == 0x5D002201:
            hits.append("spurious PIE HW assert on DRAM UMCE, data poisoning disabled")
        if self.bank_idx == 3 and self.synd & 1:
            hits.append("HPE/Dell criterion: Bank 0x03 and Synd[0]=1 -> AmdIcConfigDisableITBypass")
        if not hits:
            hits.append("solar flares, cosmic rays or bad luck")
        return hits

    def __repr__(self):
        u = self.unit
        acr = self.error_type
        xec = f"0x{self.errorcodeext:02x} ({self.errorcodeext})"
        if acr is None:
            xec += f"   !! not in {u} table"
        else:
            xec += f"   {acr}"
            if self.error_desc:
                xec += f" - {self.error_desc}"

        rows = [
            (f"MCA_STATUS_{u}", f"0x{self.status:016x}"),
            (f"MCA_STATUS_{u}[ExtErrorCode]", xec),
            (f"MCA_STATUS_{u}[ErrorCode]",
             f"0x{self.errorcode:04x}   {decode_errorcode(self.errorcode)}"),
            (f"MCA_IPID_{u}",
             f"0x{self.ipid:016x}   HwId=0x{self.ipid >> 32 & 0xFFF:03x} "
             f"McaType=0x{self.ipid >> 48 & 0xFFFF:04x}"),
        ]
        if self.syndv:
            rows += [
                (f"MCA_SYND_{u}", f"0x{self.synd:016x}"),
                (f"MCA_SYND_{u}[ErrorInformation]",
                 f"0x{self.errorinformation:04x} ({self.errorinformation})"),
                ("Synd[0]", str(self.synd & 1)),
            ]
        else:
            rows.append((f"MCA_SYND_{u}", "(SyndV=0)"))
        if self.addrv:
            rows.append((f"MCA_ADDR_{u}", f"0x{self.addr:016x}"))

        rows.append(("flags", " ".join(n for n, v in (
            ("Val", self.valid), ("Over", self.overflow), ("UC", self.uc),
            ("En", self.enabled), ("MiscV", self.miscv),
            ("AddrV", self.addrv), ("PCC", self.pcc), ("TCC", self.tcc),
            ("SyndV", self.syndv), ("Deferred", self.deferred),
            ("Poison", self.poison)) if v)))

        for p in self.check_flags():
            rows.append(("!! check", p))
        for h in self.known_issues():
            rows.append(("verdict: ", h))

        head = f"APIC 0x{self.apic:02x}   bank {self.bank_idx} -> {u}"
        return head + "\n" + tabulate(rows, tablefmt="plain",
                                      disable_numparse=True)


def parse(text):
    lines = []
    for raw in text.splitlines():
        m = HWERR_REGEX.search(raw)
        if m:
            lines.append(m["line"].strip())

    records = []
    apic = 0
    for idx, line in enumerate(lines):
        m = APIC_REGEX.search(line)
        if m:
            apic = int(m["apic"], 16)
            continue
        if line != MSR_CTX:
            continue
        msr_base = None
        qwords = {}
        for nxt in lines[idx + 1:]:
            m = MSR_REGEX.search(nxt)
            if m:
                msr_base = int(m["msr"], 16)
                continue
            m = ROW_REGEX.match(nxt)
            if m:
                off = int(m["off"], 16)
                for i, tok in enumerate(m["vals"].split()):
                    qwords[off // 8 + i] = int(tok, 16)
                continue
            if qwords:
                break
        if msr_base is not None and qwords:
            records.append(McaRecord(msr_base, qwords, apic))
    return records


if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    else:
        text = sys.stdin.read()
    found = parse(text)
    if not found:
        print("no BERT record found", file=sys.stderr)
        sys.exit(1)
    for rec in found:
        print(rec)
        print()
