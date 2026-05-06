package stas3

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script"
)

// Opcodes used for STAS v3 script detection.
const (
	opDUP         = 0x76
	opHASH160     = 0xa9
	opPUSH20      = 0x14 // push 20 bytes
	opPUSH33      = 0x21 // push 33 bytes
	opEQUALVERIFY = 0x88
	opCHECKSIG    = 0xac
	opRETURN      = 0x6a
	opFALSE       = 0x00 // OP_0 / OP_FALSE
	op2           = 0x52 // OP_2
)

// STASOutput holds the parsed fields from a STAS v3 locking script.
//
// Every standard STAS3 wire field is surfaced here. `OptionalData` is left
// as raw byte pushes — apps interpret them per their own scheme (e.g. EAC1,
// VPPA, certificate-reference, etc.) or wait for a future schema layer
// that decodes them into typed columns.
type STASOutput struct {
	// Address is the 20-byte owner/recipient hash160 (hex-encoded). For
	// DSTAS pubkey owners (33-byte push) this is the raw pubkey hex.
	Address string
	// TokenID is the 20-byte redemption PKH / token identifier (hex-encoded).
	TokenID string
	// Symbol is the optional token symbol from the legacy OP_RETURN
	// second push. DSTAS does not encode symbol in the locking script —
	// it lives in the off-chain contract OP_RETURN scheme JSON.
	Symbol string
	// IsDSTAS is true if the script uses the DSTAS direct-push-owner format.
	IsDSTAS bool
	// ClassHash is the universal asset-class identifier (sha256 of the
	// script tail with owner + action_data stripped). See class_hash.go.
	// Hex-encoded. Apps doing cross-class matching key on this value.
	ClassHash string
	// ActionKind classifies the action_data slot — one of "passive",
	// "frozen", "swap", "custom". See action_data.go for the wire format.
	ActionKind string
	// Frozen is true for frozen-state action_data (selector 0x02 or
	// bare OP_2). A frozen UTXO can still carry an inner swap descriptor.
	Frozen bool
	// ActionData is the raw push bytes (hex). Apps that need more than
	// the typed fields above can re-decode from here.
	ActionData string
	// SwapDescriptor is set when ActionKind == "swap" (or for frozen
	// UTXOs whose inner action_data is a swap leg).
	SwapDescriptor *SwapDescriptor
	// Flags is the protocol flag byte (bit 0 = freezable, bit 1 = confiscatable).
	Flags uint8
	// FreezeAuthority is the 20-byte hash160 of the freeze authority
	// PKH (or MPKH). Empty unless Flags & 0x01 (freezable) is set.
	FreezeAuthority string
	// ConfiscationAuthority is the 20-byte hash160 of the confiscation
	// authority PKH. Empty unless Flags & 0x02 (confiscatable) is set.
	ConfiscationAuthority string
	// OptionalData is the array of pushdata blobs that follow the
	// service fields (hex-encoded). Layout is application-defined.
	OptionalData []string
}

var (
	ErrNotSTAS    = errors.New("not a STAS v3 script")
	ErrTooShort   = errors.New("script too short for STAS v3")
	ErrNoOpReturn = errors.New("no OP_RETURN found")
	ErrNoTokenID  = errors.New("no tokenId after OP_RETURN")
)

// ParseSTASScript attempts to parse a locking script as STAS v3.
// Supports both DSTAS (direct-push-owner) and legacy P2PKH-style scripts.
//
// DSTAS format:
//
//	[0x14 | 0x21] {owner bytes} {action data} {template...} 0x6a {20-byte redemption PKH} {flags} {service fields...} {optional data...}
//
// Legacy P2PKH format:
//
//	76 a9 14 {20-byte hash160} 88 ac {covenant...} 6a {20-byte tokenId} [symbol]
func ParseSTASScript(s *script.Script) (*STASOutput, error) {
	if s == nil {
		return nil, ErrNotSTAS
	}

	b := *s
	if len(b) < 27 {
		return nil, ErrTooShort
	}

	// Try DSTAS format first (more common for STAS v3 / DXS SDK tokens).
	out, err := parseDSTAS(b)
	if err != nil {
		// Fall back to legacy P2PKH-style STAS.
		out, err = parseLegacySTAS(b)
		if err != nil {
			return nil, err
		}
	}

	// Class hash is the same computation for both layouts: sha256 of the
	// script tail with the first two pushes (owner + action_data) stripped.
	// For legacy STAS the "owner push" is the 5-byte P2PKH prefix; the
	// existing extract helper is push-aware so it Just Works.
	if classHash, hashErr := computeClassHashBytes(b); hashErr == nil {
		out.ClassHash = classHash
	}

	return out, nil
}

// computeClassHashBytes is the byte-slice variant of ComputeClassHash.
// Both share extractCounterpartyScript so the hash is byte-stable across
// callers.
func computeClassHashBytes(b []byte) (string, error) {
	tail, err := extractCounterpartyScript(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]), nil
}

// parseDSTAS detects the DSTAS direct-push-owner locking script format.
//
// Structure:
//   - Owner field: push of 20 bytes (0x14) or 33 bytes (0x21)
//   - Action data: OP_0 (0x00), OP_2 (0x52), or data push
//   - Template base: covenant opcodes (contains OP_RETURN internally)
//   - After OP_RETURN: redemption PKH (20 bytes), flags, service fields, optional data
func parseDSTAS(b []byte) (*STASOutput, error) {
	// Owner push must be 0x14 (20 bytes) or 0x21 (33 bytes).
	ownerPushLen := int(b[0])
	if ownerPushLen != 20 && ownerPushLen != 33 {
		return nil, ErrNotSTAS
	}

	ownerEnd := 1 + ownerPushLen
	if ownerEnd >= len(b) {
		return nil, ErrTooShort
	}

	// Extract 20-byte owner address. For 33-byte pubkey owners, we still
	// report the raw hex but note it's a compressed pubkey, not a hash160.
	var addressHex string
	if ownerPushLen == 20 {
		addressHex = hex.EncodeToString(b[1:21])
	} else {
		// 33-byte owner: store full pubkey hex (callers can hash160 if needed).
		addressHex = hex.EncodeToString(b[1:34])
	}

	// Decode action data (second push: OP_0, OP_2, or data push).
	actionStart := ownerEnd
	if actionStart >= len(b) {
		return nil, ErrTooShort
	}
	actionByte := b[actionStart]
	actionEnd := skipPush(b, actionStart)
	if actionEnd < 0 || actionEnd >= len(b) {
		return nil, ErrNotSTAS
	}
	actionPayload := extractPushPayload(b, actionStart, actionEnd)
	actionKind, frozen, swap := decodeActionData(actionPayload, actionByte)

	// Verify there's a covenant body between action data and OP_RETURN.
	// The DSTAS template base is substantial (hundreds of bytes).
	// Find OP_RETURN in the remaining script.
	opReturnIdx := -1
	for i := actionEnd; i < len(b); i++ {
		if b[i] == opRETURN {
			opReturnIdx = i
			break
		}
	}
	if opReturnIdx < 0 {
		return nil, ErrNoOpReturn
	}

	// Need at least some template bytes between action data and OP_RETURN.
	if opReturnIdx <= actionEnd {
		return nil, ErrNotSTAS
	}

	// After OP_RETURN: parse data pushes. Layout is
	//   [redemption_pkh:20B] [flags:1B] [service_fields × popcount(flags & 3)] [optional_data...]
	pushes, err := parseDataPushes(b[opReturnIdx+1:])
	if err != nil {
		return nil, fmt.Errorf("parsing post-OP_RETURN data: %w", err)
	}
	if len(pushes) == 0 || len(pushes[0]) != 20 {
		return nil, ErrNoTokenID
	}

	out := &STASOutput{
		Address:        addressHex,
		TokenID:        hex.EncodeToString(pushes[0]),
		IsDSTAS:        true,
		ActionKind:     actionKind,
		Frozen:         frozen,
		ActionData:     hex.EncodeToString(actionPayload),
		SwapDescriptor: swap,
	}

	// Flags byte (push #2 after OP_RETURN). When absent, treat as 0
	// (legacy DSTAS scripts may omit it; tail is still admittable).
	if len(pushes) >= 2 && len(pushes[1]) == 1 {
		out.Flags = pushes[1][0]
	}

	// Service fields follow the flags push, one per set bit in the low
	// nibble. Bit 0 → freeze authority; bit 1 → confiscation authority.
	// Service fields are 20-byte hash160 pushes.
	serviceIdx := 2
	if out.Flags&0x01 != 0 {
		if serviceIdx < len(pushes) && len(pushes[serviceIdx]) == 20 {
			out.FreezeAuthority = hex.EncodeToString(pushes[serviceIdx])
		}
		serviceIdx++
	}
	if out.Flags&0x02 != 0 {
		if serviceIdx < len(pushes) && len(pushes[serviceIdx]) == 20 {
			out.ConfiscationAuthority = hex.EncodeToString(pushes[serviceIdx])
		}
		serviceIdx++
	}

	// Optional data: everything after the service fields. Apps decode
	// these per their own scheme (EAC1, certificate refs, etc.).
	if serviceIdx < len(pushes) {
		out.OptionalData = make([]string, 0, len(pushes)-serviceIdx)
		for _, p := range pushes[serviceIdx:] {
			out.OptionalData = append(out.OptionalData, hex.EncodeToString(p))
		}
	}

	return out, nil
}

// extractPushPayload returns the data bytes pushed by the push operation
// at b[start..end]. For single-byte opcodes (OP_0, OP_1..OP_16) this is
// an empty slice. Used to feed action_data into decodeActionData.
func extractPushPayload(b []byte, start, end int) []byte {
	if start >= end || start >= len(b) {
		return nil
	}
	op := b[start]
	switch {
	case op == 0x00 || (op >= 0x4f && op <= 0x60):
		// Bare opcode — no payload bytes.
		return nil
	case op >= 0x01 && op <= 0x4b:
		return b[start+1 : end]
	case op == 0x4c: // OP_PUSHDATA1
		return b[start+2 : end]
	case op == 0x4d: // OP_PUSHDATA2
		return b[start+3 : end]
	case op == 0x4e: // OP_PUSHDATA4
		return b[start+5 : end]
	}
	return nil
}

// parseLegacySTAS detects the P2PKH-prefix STAS locking script format.
//
// Structure: 76 a9 14 {20} 88 ac {covenant...} 6a {20-byte tokenId} [symbol]
func parseLegacySTAS(b []byte) (*STASOutput, error) {
	// Check P2PKH prefix: OP_DUP OP_HASH160 OP_PUSH20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	if b[0] != opDUP || b[1] != opHASH160 || b[2] != opPUSH20 {
		return nil, ErrNotSTAS
	}
	if len(b) < 27 {
		return nil, ErrTooShort
	}
	address := hex.EncodeToString(b[3:23])
	if b[23] != opEQUALVERIFY || b[24] != opCHECKSIG {
		return nil, ErrNotSTAS
	}

	// Find OP_RETURN after the P2PKH prefix.
	opReturnIdx := -1
	for i := 25; i < len(b); i++ {
		if b[i] == opRETURN {
			opReturnIdx = i
			break
		}
	}
	if opReturnIdx < 0 {
		return nil, ErrNoOpReturn
	}

	// Require covenant body between P2PKH and OP_RETURN.
	if opReturnIdx <= 25 {
		return nil, ErrNotSTAS
	}

	// Parse data pushes after OP_RETURN.
	pushes, err := parseDataPushes(b[opReturnIdx+1:])
	if err != nil {
		return nil, fmt.Errorf("parsing OP_RETURN data: %w", err)
	}
	if len(pushes) == 0 || len(pushes[0]) != 20 {
		return nil, ErrNoTokenID
	}

	out := &STASOutput{
		Address: address,
		TokenID: hex.EncodeToString(pushes[0]),
	}
	if len(pushes) > 1 && len(pushes[1]) > 0 {
		out.Symbol = string(pushes[1])
	}

	return out, nil
}

// IsSTASScript returns true if the locking script matches any STAS v3 pattern.
func IsSTASScript(s *script.Script) bool {
	_, err := ParseSTASScript(s)
	return err == nil
}

// skipPush advances past a single push operation at b[offset], returning the
// index of the byte after the pushed data. Returns -1 on error.
func skipPush(b []byte, offset int) int {
	if offset >= len(b) {
		return -1
	}
	op := b[offset]

	// OP_0, OP_1-OP_16, OP_1NEGATE — single-byte opcodes, no data
	if op == 0x00 || (op >= 0x4f && op <= 0x60) {
		return offset + 1
	}

	// Direct push 0x01-0x4b: op bytes of data follow
	if op >= 0x01 && op <= 0x4b {
		end := offset + 1 + int(op)
		if end > len(b) {
			return -1
		}
		return end
	}

	// OP_PUSHDATA1
	if op == 0x4c {
		if offset+2 > len(b) {
			return -1
		}
		n := int(b[offset+1])
		end := offset + 2 + n
		if end > len(b) {
			return -1
		}
		return end
	}

	// OP_PUSHDATA2
	if op == 0x4d {
		if offset+3 > len(b) {
			return -1
		}
		n := int(b[offset+1]) | int(b[offset+2])<<8
		end := offset + 3 + n
		if end > len(b) {
			return -1
		}
		return end
	}

	// OP_PUSHDATA4
	if op == 0x4e {
		if offset+5 > len(b) {
			return -1
		}
		n := int(b[offset+1]) | int(b[offset+2])<<8 | int(b[offset+3])<<16 | int(b[offset+4])<<24
		end := offset + 5 + n
		if end > len(b) {
			return -1
		}
		return end
	}

	// Any other opcode (non-push) — treat as single byte
	return offset + 1
}

// parseDataPushes extracts data push operands from a script fragment.
// Handles OP_0, OP_PUSHDATA1/2/4, and direct push opcodes (0x01-0x4b).
// Stops at the first non-push opcode.
func parseDataPushes(data []byte) ([][]byte, error) {
	var pushes [][]byte
	i := 0
	for i < len(data) {
		op := data[i]
		i++

		switch {
		case op == 0x00:
			// OP_0 — push empty
			pushes = append(pushes, []byte{})

		case op >= 0x01 && op <= 0x4b:
			// Direct push: op bytes of data follow
			end := i + int(op)
			if end > len(data) {
				return pushes, fmt.Errorf("push %d overflows at offset %d", op, i-1)
			}
			pushes = append(pushes, data[i:end])
			i = end

		case op == 0x4c:
			// OP_PUSHDATA1: next byte is length
			if i >= len(data) {
				return pushes, fmt.Errorf("OP_PUSHDATA1 missing length at offset %d", i-1)
			}
			n := int(data[i])
			i++
			end := i + n
			if end > len(data) {
				return pushes, fmt.Errorf("OP_PUSHDATA1 overflows at offset %d", i-2)
			}
			pushes = append(pushes, data[i:end])
			i = end

		case op == 0x4d:
			// OP_PUSHDATA2: next 2 bytes (LE) are length
			if i+2 > len(data) {
				return pushes, fmt.Errorf("OP_PUSHDATA2 missing length at offset %d", i-1)
			}
			n := int(data[i]) | int(data[i+1])<<8
			i += 2
			end := i + n
			if end > len(data) {
				return pushes, fmt.Errorf("OP_PUSHDATA2 overflows at offset %d", i-4)
			}
			pushes = append(pushes, data[i:end])
			i = end

		case op == 0x4e:
			// OP_PUSHDATA4: next 4 bytes (LE) are length
			if i+4 > len(data) {
				return pushes, fmt.Errorf("OP_PUSHDATA4 missing length at offset %d", i-1)
			}
			n := int(data[i]) | int(data[i+1])<<8 | int(data[i+2])<<16 | int(data[i+3])<<24
			i += 4
			end := i + n
			if end > len(data) {
				return pushes, fmt.Errorf("OP_PUSHDATA4 overflows at offset %d", i-6)
			}
			pushes = append(pushes, data[i:end])
			i = end

		default:
			// Non-push opcode — stop parsing data pushes.
			return pushes, nil
		}
	}
	return pushes, nil
}
