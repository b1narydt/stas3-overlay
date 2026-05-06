package stas3

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TopicManager validates incoming transactions for STAS v3 token outputs.
// It admits any output whose locking script parses as STAS v3.
//
// When ExpectedClassHash is set (hex32), the manager additionally rejects
// outputs whose computed class_hash does not match — letting an operator
// run a per-class instance (e.g., stas3-usd, stas3-gold, stas3-energy)
// from the same binary. When ExpectedClassHash is empty, the manager
// admits every STAS v3 output regardless of class (the legacy default).
type TopicManager struct {
	// ExpectedClassHash, when non-empty, restricts admissions to
	// outputs whose computed class_hash equals this value (hex32). This
	// is the cryptographic per-class scope predicate; the topic name is
	// purely cosmetic.
	ExpectedClassHash string
}

// NewTopicManager creates a STAS v3 topic manager that admits every
// STAS v3 output regardless of class — the legacy admit-all default.
//
// To deploy a per-class instance, use NewClassScopedTopicManager.
func NewTopicManager() *TopicManager {
	return &TopicManager{}
}

// NewClassScopedTopicManager creates a STAS v3 topic manager that admits
// only outputs whose class_hash matches `expectedClassHash` (hex32).
// Pass an empty string to fall back to admit-all behavior.
func NewClassScopedTopicManager(expectedClassHash string) *TopicManager {
	return &TopicManager{ExpectedClassHash: expectedClassHash}
}

// IdentifyAdmissibleOutputs parses the BEEF, extracts the transaction,
// and returns indices of outputs that contain valid STAS v3 locking
// scripts (and, when ExpectedClassHash is set, that match it).
func (m *TopicManager) IdentifyAdmissibleOutputs(_ context.Context, beef []byte, _ []uint32) (overlay.AdmittanceInstructions, error) {
	_, tx, txid, err := transaction.ParseBeef(beef)
	if err != nil {
		return overlay.AdmittanceInstructions{}, fmt.Errorf("stas3: parsing BEEF: %w", err)
	}
	if tx == nil {
		return overlay.AdmittanceInstructions{}, fmt.Errorf("stas3: BEEF contains no transaction")
	}

	var admissible []uint32
	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		parsed, err := ParseSTASScript(out.LockingScript)
		if err != nil {
			slog.Debug("stas3: output not STAS v3",
				"txid", txid,
				"vout", i,
				"reason", err.Error(),
			)
			continue
		}
		// Per-class scope predicate. When ExpectedClassHash is empty,
		// admit every STAS v3 output (legacy default).
		if m.ExpectedClassHash != "" && parsed.ClassHash != m.ExpectedClassHash {
			slog.Debug("stas3: rejecting output, class_hash mismatch",
				"txid", txid,
				"vout", i,
				"got", parsed.ClassHash,
				"want", m.ExpectedClassHash,
			)
			continue
		}
		admissible = append(admissible, uint32(i)) //nolint:gosec // index bounded by tx outputs
		slog.Info("stas3: admitting output",
			"txid", txid,
			"vout", i,
			"tokenId", parsed.TokenID,
			"classHash", parsed.ClassHash,
			"actionKind", parsed.ActionKind,
		)
	}

	return overlay.AdmittanceInstructions{
		OutputsToAdmit: admissible,
	}, nil
}

// IdentifyNeededInputs returns nil — STAS v3 has built-in protections
// and BEEF carries the ancestry chain for SPV verification.
func (m *TopicManager) IdentifyNeededInputs(_ context.Context, _ []byte) ([]*transaction.Outpoint, error) {
	return nil, nil
}

// GetDocumentation returns a human-readable description of the STAS v3 topic.
func (m *TopicManager) GetDocumentation() string {
	doc := "STAS v3 token topic manager. " +
		"Admits outputs with valid STAS v3 locking scripts: " +
		"P2PKH-prefix or DSTAS-direct-push owner + covenant body + OP_RETURN " +
		"with 20-byte tokenId, plus flags/service_fields/optional_data. " +
		"Supports issuance, transfer, split, merge, freeze/unfreeze, confiscate, " +
		"redeem, and swap-mark/execute/cancel outputs."
	if m.ExpectedClassHash != "" {
		doc += " This instance is scoped to class_hash=" + m.ExpectedClassHash + "."
	}
	return doc
}

// GetMetaData returns overlay metadata for tm_stas3.
func (m *TopicManager) GetMetaData() *overlay.MetaData {
	return TopicManagerMetaData()
}
