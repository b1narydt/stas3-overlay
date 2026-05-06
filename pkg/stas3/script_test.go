package stas3

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
)

// buildLegacySTASScript constructs a P2PKH-style STAS v3 locking script for testing.
func buildLegacySTASScript(recipientHash160, tokenID []byte, symbol string, covenantLen int) *script.Script {
	// P2PKH prefix
	s := []byte{opDUP, opHASH160, opPUSH20}
	s = append(s, recipientHash160...)
	s = append(s, opEQUALVERIFY, opCHECKSIG)

	// Covenant body — fill with OP_NOP (0x61) to simulate real covenant.
	for i := 0; i < covenantLen; i++ {
		s = append(s, 0x61) // OP_NOP
	}

	// OP_RETURN
	s = append(s, opRETURN)

	// Push tokenID (20 bytes)
	s = append(s, byte(len(tokenID)))
	s = append(s, tokenID...)

	// Push symbol (optional)
	if symbol != "" {
		symBytes := []byte(symbol)
		s = append(s, byte(len(symBytes)))
		s = append(s, symBytes...)
	}

	sc := script.Script(s)
	return &sc
}

// buildDSTASScript constructs a DSTAS direct-push-owner locking script for testing.
// Structure: [0x14] [20-byte owner] [actionData] [template body...] [0x6a] [20-byte redemptionPkh] [flags]
func buildDSTASScript(ownerHash160, redemptionPkh []byte, actionDataOpcode byte, templateLen int) *script.Script {
	s := []byte{opPUSH20}
	s = append(s, ownerHash160...)

	// Action data: single opcode (OP_0 for normal, OP_2 for frozen)
	s = append(s, actionDataOpcode)

	// Template body — fill with OP_NOP to simulate the DSTAS covenant template.
	for i := 0; i < templateLen; i++ {
		s = append(s, 0x61) // OP_NOP
	}

	// OP_RETURN (marks start of post-covenant data section)
	s = append(s, opRETURN)

	// Redemption PKH = tokenId (20 bytes)
	s = append(s, byte(len(redemptionPkh)))
	s = append(s, redemptionPkh...)

	// Flags (1 byte: bit 0 = freezable, bit 1 = confiscatable)
	s = append(s, 0x01, 0x03) // push 1 byte: 0x03 (freezable + confiscatable)

	sc := script.Script(s)
	return &sc
}

// buildDSTASScriptWithData constructs a DSTAS script with data-push action data.
func buildDSTASScriptWithData(ownerHash160, redemptionPkh, actionData []byte, templateLen int) *script.Script {
	s := []byte{opPUSH20}
	s = append(s, ownerHash160...)

	// Action data as data push
	s = append(s, byte(len(actionData)))
	s = append(s, actionData...)

	// Template body
	for i := 0; i < templateLen; i++ {
		s = append(s, 0x61)
	}

	s = append(s, opRETURN)
	s = append(s, byte(len(redemptionPkh)))
	s = append(s, redemptionPkh...)
	s = append(s, 0x01, 0x00) // flags: 0x00

	sc := script.Script(s)
	return &sc
}

// --- DSTAS tests ---

func TestParseDSTAS_Valid(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")

	s := buildDSTASScript(owner, tokenID, opFALSE, 200)
	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("expected valid DSTAS script, got error: %v", err)
	}
	if !out.IsDSTAS {
		t.Error("expected IsDSTAS=true")
	}
	if out.Address != "aabbccddee0011223344aabbccddee0011223344" {
		t.Errorf("address = %q, want aabbccddee0011223344aabbccddee0011223344", out.Address)
	}
	if out.TokenID != "1122334455667788990011223344556677889900" {
		t.Errorf("tokenId = %q, want 1122334455667788990011223344556677889900", out.TokenID)
	}
}

func TestParseDSTAS_Frozen(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")

	// OP_2 (0x52) indicates frozen action data
	s := buildDSTASScript(owner, tokenID, op2, 150)
	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("expected valid frozen DSTAS script, got error: %v", err)
	}
	if !out.IsDSTAS {
		t.Error("expected IsDSTAS=true")
	}
	if out.TokenID != "1122334455667788990011223344556677889900" {
		t.Errorf("tokenId = %q", out.TokenID)
	}
}

func TestParseDSTAS_WithSwapActionData(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")

	// Swap action data: 0x01 + 32-byte script hash + 20-byte requested PKH + 8-byte rate
	actionData := make([]byte, 61)
	actionData[0] = 0x01 // swap action kind
	// rest is zeroed (valid for testing)

	s := buildDSTASScriptWithData(owner, tokenID, actionData, 200)
	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("expected valid DSTAS with swap data, got error: %v", err)
	}
	if !out.IsDSTAS {
		t.Error("expected IsDSTAS=true")
	}
}

func TestParseDSTAS_TooShort(t *testing.T) {
	// Just the owner push, nothing else.
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	s := []byte{opPUSH20}
	s = append(s, owner...)
	sc := script.Script(s)
	_, err := ParseSTASScript(&sc)
	if err == nil {
		t.Fatal("expected error for truncated DSTAS, got nil")
	}
}

func TestParseDSTAS_NoOpReturn(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	s := []byte{opPUSH20}
	s = append(s, owner...)
	s = append(s, opFALSE) // action data
	// Template body with no OP_RETURN
	for i := 0; i < 100; i++ {
		s = append(s, 0x61)
	}
	sc := script.Script(s)
	_, err := ParseSTASScript(&sc)
	if err == nil {
		t.Fatal("expected error for DSTAS with no OP_RETURN, got nil")
	}
}

func TestParseDSTAS_NoTokenIDAfterOpReturn(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	s := []byte{opPUSH20}
	s = append(s, owner...)
	s = append(s, opFALSE) // action data
	for i := 0; i < 50; i++ {
		s = append(s, 0x61)
	}
	s = append(s, opRETURN)
	// Only 10 bytes after OP_RETURN (not 20)
	s = append(s, 0x0a) // push 10
	s = append(s, make([]byte, 10)...)
	sc := script.Script(s)
	_, err := ParseSTASScript(&sc)
	if err == nil {
		t.Fatal("expected error for DSTAS with bad tokenId length, got nil")
	}
}

func TestParseDSTAS_33ByteOwner(t *testing.T) {
	// 33-byte compressed public key as owner
	owner := make([]byte, 33)
	owner[0] = 0x02 // compressed pubkey prefix
	for i := 1; i < 33; i++ {
		owner[i] = byte(i)
	}
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")

	s := []byte{opPUSH33}
	s = append(s, owner...)
	s = append(s, opFALSE) // action data
	for i := 0; i < 100; i++ {
		s = append(s, 0x61)
	}
	s = append(s, opRETURN)
	s = append(s, byte(len(tokenID)))
	s = append(s, tokenID...)
	s = append(s, 0x01, 0x00) // flags

	sc := script.Script(s)
	out, err := ParseSTASScript(&sc)
	if err != nil {
		t.Fatalf("expected valid DSTAS with 33-byte owner, got: %v", err)
	}
	if !out.IsDSTAS {
		t.Error("expected IsDSTAS=true")
	}
	if out.Address != hex.EncodeToString(owner) {
		t.Errorf("address = %q, want %q", out.Address, hex.EncodeToString(owner))
	}
}

// --- Legacy P2PKH-style STAS tests ---

func TestParseLegacySTAS_Valid(t *testing.T) {
	recipientHash, _ := hex.DecodeString("0011223344556677889900112233445566778899")
	tokenID, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")

	s := buildLegacySTASScript(recipientHash, tokenID, "MWTT", 100)
	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("expected valid legacy STAS script, got error: %v", err)
	}
	if out.IsDSTAS {
		t.Error("expected IsDSTAS=false for legacy script")
	}
	if out.Address != "0011223344556677889900112233445566778899" {
		t.Errorf("address = %q", out.Address)
	}
	if out.TokenID != "aabbccddee0011223344aabbccddee0011223344" {
		t.Errorf("tokenId = %q", out.TokenID)
	}
	if out.Symbol != "MWTT" {
		t.Errorf("symbol = %q, want MWTT", out.Symbol)
	}
}

func TestParseLegacySTAS_NoSymbol(t *testing.T) {
	recipientHash, _ := hex.DecodeString("0011223344556677889900112233445566778899")
	tokenID, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")

	s := buildLegacySTASScript(recipientHash, tokenID, "", 50)
	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("expected valid STAS script, got error: %v", err)
	}
	if out.Symbol != "" {
		t.Errorf("symbol = %q, want empty", out.Symbol)
	}
}

func TestParseLegacySTAS_NoCovenant(t *testing.T) {
	recipientHash, _ := hex.DecodeString("0011223344556677889900112233445566778899")
	tokenID, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")

	// Zero-length covenant — bare P2PKH + OP_RETURN, not STAS.
	s := buildLegacySTASScript(recipientHash, tokenID, "", 0)
	_, err := ParseSTASScript(s)
	if err == nil {
		t.Fatal("expected error for bare P2PKH + OP_RETURN")
	}
}

func TestParseLegacySTAS_P2PKHOnly(t *testing.T) {
	s := []byte{opDUP, opHASH160, opPUSH20}
	s = append(s, make([]byte, 20)...)
	s = append(s, opEQUALVERIFY, opCHECKSIG)
	sc := script.Script(s)
	_, err := ParseSTASScript(&sc)
	if err == nil {
		t.Fatal("expected error for plain P2PKH, got nil")
	}
}

func TestParseLegacySTAS_BadTokenIDLength(t *testing.T) {
	recipientHash, _ := hex.DecodeString("0011223344556677889900112233445566778899")
	tokenID, _ := hex.DecodeString("aabbccddee0011223344") // only 10 bytes

	s := buildLegacySTASScript(recipientHash, tokenID, "", 50)
	_, err := ParseSTASScript(s)
	if err != ErrNoTokenID {
		t.Fatalf("expected ErrNoTokenID, got: %v", err)
	}
}

// --- General tests ---

func TestParseSTASScript_TooShort(t *testing.T) {
	sc := script.Script([]byte{0x76, 0xa9})
	_, err := ParseSTASScript(&sc)
	if err != ErrTooShort {
		t.Fatalf("expected ErrTooShort, got: %v", err)
	}
}

func TestParseSTASScript_Nil(t *testing.T) {
	_, err := ParseSTASScript(nil)
	if err != ErrNotSTAS {
		t.Fatalf("expected ErrNotSTAS, got: %v", err)
	}
}

func TestIsSTASScript_DSTAS(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	valid := buildDSTASScript(owner, tokenID, opFALSE, 100)
	if !IsSTASScript(valid) {
		t.Error("expected IsSTASScript=true for valid DSTAS script")
	}
}

func TestIsSTASScript_Legacy(t *testing.T) {
	recipientHash, _ := hex.DecodeString("0011223344556677889900112233445566778899")
	tokenID, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	valid := buildLegacySTASScript(recipientHash, tokenID, "TST", 80)
	if !IsSTASScript(valid) {
		t.Error("expected IsSTASScript=true for valid legacy script")
	}
}

func TestIsSTASScript_Invalid(t *testing.T) {
	invalid := script.Script([]byte{0x00, 0x01, 0x02})
	if IsSTASScript(&invalid) {
		t.Error("expected IsSTASScript=false for invalid script")
	}
}

func TestParseDataPushes_PUSHDATA1(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	fragment := []byte{0x4c, 100} // OP_PUSHDATA1, length=100
	fragment = append(fragment, data...)

	pushes, err := parseDataPushes(fragment)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pushes) != 1 {
		t.Fatalf("expected 1 push, got %d", len(pushes))
	}
	if len(pushes[0]) != 100 {
		t.Errorf("push length = %d, want 100", len(pushes[0]))
	}
}

func TestSkipPush(t *testing.T) {
	// OP_0
	b := []byte{0x00, 0xff}
	if got := skipPush(b, 0); got != 1 {
		t.Errorf("OP_0: skipPush = %d, want 1", got)
	}

	// Direct push of 5 bytes
	b = []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff}
	if got := skipPush(b, 0); got != 6 {
		t.Errorf("direct push 5: skipPush = %d, want 6", got)
	}

	// OP_PUSHDATA1 with 3 bytes
	b = []byte{0x4c, 0x03, 0xaa, 0xbb, 0xcc, 0xff}
	if got := skipPush(b, 0); got != 5 {
		t.Errorf("PUSHDATA1: skipPush = %d, want 5", got)
	}

	// OP_1 (0x51) — single-byte opcode
	b = []byte{0x51, 0xff}
	if got := skipPush(b, 0); got != 1 {
		t.Errorf("OP_1: skipPush = %d, want 1", got)
	}
}
