package stas3

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TopicManager validates incoming transactions for STAS v3 token outputs.
// It admits only outputs containing valid STAS v3 locking scripts with a
// P2PKH prefix, covenant body, and OP_RETURN carrying a 20-byte tokenId.
type TopicManager struct{}

// NewTopicManager creates a new STAS v3 topic manager.
func NewTopicManager() *TopicManager {
	return &TopicManager{}
}

// IdentifyAdmissibleOutputs parses the BEEF, extracts the transaction,
// and returns indices of outputs that contain valid STAS v3 locking scripts.
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
		admissible = append(admissible, uint32(i)) //nolint:gosec // index bounded by tx outputs
		slog.Info("stas3: admitting output",
			"txid", txid,
			"vout", i,
			"tokenId", parsed.TokenID,
			"address", parsed.Address,
			"symbol", parsed.Symbol,
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
	return "STAS v3 token topic manager. " +
		"Admits outputs with valid STAS v3 locking scripts: " +
		"P2PKH prefix + covenant body + OP_RETURN with 20-byte tokenId. " +
		"Supports token issuance, transfer, split, merge, and redemption outputs."
}

// GetMetaData returns overlay metadata for tm_stas3.
func (m *TopicManager) GetMetaData() *overlay.MetaData {
	return TopicManagerMetaData()
}
