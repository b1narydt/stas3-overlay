package stas3

import (
	"github.com/bsv-blockchain/go-sdk/overlay"
)

// TopicName is the overlay topic for STAS v3 tokens.
const TopicName = "tm_stas3"

// LookupServiceName is the overlay lookup service for STAS v3 tokens.
const LookupServiceName = "ls_stas3"

// MongoCollection is the MongoDB collection name for STAS3 UTXO records.
const MongoCollection = "stas3_utxos"

// STASRecord represents an indexed STAS v3 token UTXO in MongoDB.
//
// The record exposes every standard STAS3 wire field plus the universal
// `ClassHash` (sha256 of the locking-script tail with owner + action_data
// stripped — the cross-overlay routing key). Apps doing cross-class
// matching key on the swap descriptor's `RequestedScriptHash` against
// peer overlays' `ClassHash` values.
//
// Field tags use `omitempty` so untouched optional fields are absent in
// both BSON and JSON projections — keeps existing client decoders that
// only read the original five fields working unchanged.
type STASRecord struct {
	// --- core identity (always populated) ---
	TxID        string `bson:"txid"        json:"txid"`
	Vout        uint32 `bson:"vout"        json:"vout"`
	TokenID     string `bson:"tokenId"     json:"tokenId"`
	Address     string `bson:"address"     json:"address"`
	Symbol      string `bson:"symbol"      json:"symbol,omitempty"`
	Satoshis    uint64 `bson:"satoshis"    json:"satoshis"`
	IsDSTAS     bool   `bson:"isDstas"     json:"isDstas"`
	Spent       bool   `bson:"spent"       json:"spent"`
	SpendTxID   string `bson:"spendTxid"   json:"spendTxid,omitempty"`
	BlockHeight uint32 `bson:"blockHeight" json:"blockHeight,omitempty"`

	// --- universal cross-overlay key ---
	// ClassHash is sha256(extractCounterpartyScript(lockingScript)).
	// Apps query peer overlays for offers whose
	// SwapRequestedScriptHash == this overlay's expected class hash.
	ClassHash string `bson:"classHash,omitempty" json:"classHash,omitempty"`

	// --- action_data projection ---
	// ActionKind is one of "passive", "frozen", "swap", "custom".
	ActionKind string `bson:"actionKind,omitempty" json:"actionKind,omitempty"`
	// Frozen is true when the action_data marks the UTXO frozen
	// (selector 0x02 or bare OP_2). A frozen UTXO can still carry an
	// inner swap descriptor.
	Frozen bool `bson:"frozen,omitempty" json:"frozen,omitempty"`
	// ActionData is the raw push bytes (hex) for apps that need fields
	// beyond the typed surface (e.g. chained swap legs, custom kinds).
	ActionData string `bson:"actionData,omitempty" json:"actionData,omitempty"`
	// ActionRecordPayload is the bytes AFTER the selector for
	// confiscation / freeze / custom kinds (hex). Empty for swap and
	// the passive / frozen-empty kinds. Lets apps decode SDK-specific
	// authority records without re-parsing.
	ActionRecordPayload string `bson:"actionRecordPayload,omitempty" json:"actionRecordPayload,omitempty"`

	// --- swap descriptor (set when ActionKind=="swap" or frozen-swap) ---
	SwapRequestedScriptHash string `bson:"swapRequestedScriptHash,omitempty" json:"swapRequestedScriptHash,omitempty"`
	SwapRequestedPkh        string `bson:"swapRequestedPkh,omitempty"        json:"swapRequestedPkh,omitempty"`
	SwapRateNumerator       uint32 `bson:"swapRateNumerator,omitempty"       json:"swapRateNumerator,omitempty"`
	SwapRateDenominator     uint32 `bson:"swapRateDenominator,omitempty"     json:"swapRateDenominator,omitempty"`
	SwapHasNext             bool   `bson:"swapHasNext,omitempty"             json:"swapHasNext,omitempty"`

	// --- protocol flags + authorities ---
	// Flags is the protocol flag byte. Bit 0 = freezable, bit 1 = confiscatable.
	Flags uint8 `bson:"flags,omitempty" json:"flags,omitempty"`
	// FreezeAuthority is the 20-byte hash160 (hex) of the freeze
	// authority. Set only when Flags & 0x01.
	FreezeAuthority string `bson:"freezeAuthority,omitempty" json:"freezeAuthority,omitempty"`
	// ConfiscationAuthority is the 20-byte hash160 (hex) of the
	// confiscation authority. Set only when Flags & 0x02.
	ConfiscationAuthority string `bson:"confiscationAuthority,omitempty" json:"confiscationAuthority,omitempty"`

	// --- application-defined optional_data ---
	// OptionalData is the array of pushdata blobs (hex) that follow the
	// service fields. The base overlay does not interpret them — apps
	// decode per their own scheme (EAC1, VPPA, certificate refs, …) or
	// a future schema layer types them into named columns.
	OptionalData []string `bson:"optionalData,omitempty" json:"optionalData,omitempty"`
}

// STASQuery represents a lookup query to ls_stas3.
// All fields are optional — unset fields match all entries.
//
// `unspent_only` is preserved for backwards compatibility; new code
// should use the explicit `spent` filter.
type STASQuery struct {
	// --- core identity filters (existing) ---
	TokenID     string `json:"tokenId,omitempty"`
	Address     string `json:"address,omitempty"`
	UnspentOnly bool   `json:"unspentOnly,omitempty"`

	// --- universal cross-overlay key ---
	// ClassHash filters by the universal asset-class identifier.
	// Useful for verifying "this overlay actually serves the class I
	// think it does" before issuing further queries.
	ClassHash string `json:"classHash,omitempty"`

	// --- action_data filters ---
	ActionKind string `json:"actionKind,omitempty"`
	FrozenOnly bool   `json:"frozenOnly,omitempty"`

	// --- swap-discovery filters ---
	// SwapRequestedScriptHash filters to swap-marked UTXOs whose
	// descriptor wants the named asset class. Apps doing cross-class
	// matching set this to their *own* overlay's class_hash to find
	// inbound offers.
	SwapRequestedScriptHash string `json:"swapRequestedScriptHash,omitempty"`
	// SwapRequestedPkh filters to offers wanting delivery to a specific PKH.
	SwapRequestedPkh string `json:"swapRequestedPkh,omitempty"`

	// --- direct outpoint lookup ---
	TxID string  `json:"txid,omitempty"`
	Vout *uint32 `json:"vout,omitempty"` // pointer so 0 is a valid filter value

	// --- pagination (optional; defaults to no limit if both zero) ---
	Limit int64 `json:"limit,omitempty"`
	Skip  int64 `json:"skip,omitempty"`
}

// TopicManagerMetaData returns overlay metadata for tm_stas3.
func TopicManagerMetaData() *overlay.MetaData {
	return &overlay.MetaData{
		Name:        TopicName,
		Description: "STAS v3 token overlay — admits outputs with valid STAS v3 locking scripts. Set STAS3_CLASS_HASH to scope to a single asset class.",
		Version:     "1.1.0",
	}
}

// LookupServiceMetaData returns overlay metadata for ls_stas3.
func LookupServiceMetaData() *overlay.MetaData {
	return &overlay.MetaData{
		Name:        LookupServiceName,
		Description: "STAS v3 token lookup — supports filters by tokenId, address, classHash, actionKind, swapRequestedScriptHash, frozenOnly, txid+vout, plus the legacy unspentOnly/spent flag.",
		Version:     "1.1.0",
	}
}
