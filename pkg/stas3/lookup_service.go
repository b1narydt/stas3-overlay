package stas3

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// LookupService indexes admitted STAS v3 token UTXOs in MongoDB and answers
// queries by all standard STAS3 fields plus the universal class_hash,
// action_kind, and swap descriptor projections.
type LookupService struct {
	col *mongo.Collection
}

// NewLookupService creates a new STAS v3 lookup service backed by MongoDB.
func NewLookupService(db *mongo.Database) *LookupService {
	return &LookupService{
		col: db.Collection(MongoCollection),
	}
}

// EnsureIndexes creates the MongoDB indexes for efficient token queries.
// Call this once at startup.
func (ls *LookupService) EnsureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "txid", Value: 1}, {Key: "vout", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "tokenId", Value: 1}, {Key: "spent", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "address", Value: 1}, {Key: "spent", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "tokenId", Value: 1}, {Key: "address", Value: 1}, {Key: "spent", Value: 1}},
		},
		// Universal cross-overlay routing key. Indexing it lets clients
		// confirm "this overlay actually serves the class I expect" and
		// is the basis for cross-overlay swap discovery.
		{
			Keys: bson.D{{Key: "classHash", Value: 1}, {Key: "spent", Value: 1}},
		},
		// Action-data projections.
		{
			Keys: bson.D{{Key: "actionKind", Value: 1}, {Key: "spent", Value: 1}},
		},
		// Swap-discovery composite. A taker on a GOLD overlay finds
		// inbound USD offers by querying any USD overlay for
		// swapRequestedScriptHash == H_GOLD.
		{
			Keys: bson.D{
				{Key: "actionKind", Value: 1},
				{Key: "swapRequestedScriptHash", Value: 1},
				{Key: "spent", Value: 1},
			},
		},
	}
	_, err := ls.col.Indexes().CreateMany(ctx, indexes)
	return err
}

// compile-time check.
var _ engine.LookupService = (*LookupService)(nil)

func (ls *LookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if len(payload.AtomicBEEF) == 0 {
		return fmt.Errorf("ls_stas3: empty AtomicBEEF")
	}

	// Parse the BEEF to extract the transaction and its outputs.
	_, tx, txid, err := transaction.ParseBeef(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("ls_stas3: parsing AtomicBEEF: %w", err)
	}
	if tx == nil {
		return fmt.Errorf("ls_stas3: BEEF contains no transaction")
	}

	idx := payload.OutputIndex
	if int(idx) >= len(tx.Outputs) {
		return fmt.Errorf("ls_stas3: output index %d out of range (tx has %d outputs)", idx, len(tx.Outputs))
	}

	out := tx.Outputs[idx]
	parsed, err := ParseSTASScript(out.LockingScript)
	if err != nil {
		return fmt.Errorf("ls_stas3: not a STAS v3 script: %w", err)
	}

	record := STASRecord{
		TxID:                  txid.String(),
		Vout:                  idx,
		TokenID:               parsed.TokenID,
		Address:               parsed.Address,
		Symbol:                parsed.Symbol,
		Satoshis:              out.Satoshis,
		IsDSTAS:               parsed.IsDSTAS,
		ClassHash:             parsed.ClassHash,
		ActionKind:            parsed.ActionKind,
		Frozen:                parsed.Frozen,
		ActionData:            parsed.ActionData,
		Flags:                 parsed.Flags,
		FreezeAuthority:       parsed.FreezeAuthority,
		ConfiscationAuthority: parsed.ConfiscationAuthority,
		OptionalData:          parsed.OptionalData,
	}
	if parsed.SwapDescriptor != nil {
		record.SwapRequestedScriptHash = parsed.SwapDescriptor.RequestedScriptHash
		record.SwapRequestedPkh = parsed.SwapDescriptor.RequestedPkh
		record.SwapRateNumerator = parsed.SwapDescriptor.RateNumerator
		record.SwapRateDenominator = parsed.SwapDescriptor.RateDenominator
		record.SwapHasNext = parsed.SwapDescriptor.HasNext
	}

	filter := bson.M{"txid": record.TxID, "vout": record.Vout}
	opts := options.Replace().SetUpsert(true)
	if _, err = ls.col.ReplaceOne(ctx, filter, record, opts); err != nil {
		return fmt.Errorf("ls_stas3: upserting record: %w", err)
	}

	slog.Info("ls_stas3: indexed output",
		"outpoint", fmt.Sprintf("%s:%d", record.TxID, record.Vout),
		"tokenId", record.TokenID,
		"classHash", record.ClassHash,
		"actionKind", record.ActionKind,
		"satoshis", record.Satoshis,
	)

	return nil
}

func (ls *LookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	filter := bson.M{
		"txid": payload.Outpoint.Txid.String(),
		"vout": payload.Outpoint.Index,
	}
	update := bson.M{
		"$set": bson.M{
			"spent":     true,
			"spendTxid": payload.SpendingTxid.String(),
		},
	}
	_, err := ls.col.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("ls_stas3: marking spent: %w", err)
	}

	slog.Info("ls_stas3: output spent",
		"outpoint", fmt.Sprintf("%s:%d", payload.Outpoint.Txid.String(), payload.Outpoint.Index),
		"spendTxid", payload.SpendingTxid.String(),
	)
	return nil
}

func (ls *LookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, _ string) error {
	return ls.deleteRecord(ctx, outpoint)
}

func (ls *LookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	return ls.deleteRecord(ctx, outpoint)
}

func (ls *LookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, _ uint64) error {
	filter := bson.M{"txid": txid.String()}
	update := bson.M{"$set": bson.M{"blockHeight": blockHeight}}
	_, err := ls.col.UpdateMany(ctx, filter, update)
	return err
}

func (ls *LookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	var q STASQuery
	if err := json.Unmarshal(question.Query, &q); err != nil {
		return nil, fmt.Errorf("ls_stas3: parsing query: %w", err)
	}

	filter := buildLookupFilter(&q)

	findOpts := options.Find()
	if q.Limit > 0 {
		findOpts.SetLimit(q.Limit)
	}
	if q.Skip > 0 {
		findOpts.SetSkip(q.Skip)
	}

	cursor, err := ls.col.Find(ctx, filter, findOpts)
	if err != nil {
		return nil, fmt.Errorf("ls_stas3: querying MongoDB: %w", err)
	}
	defer cursor.Close(ctx)

	var records []STASRecord
	if err := cursor.All(ctx, &records); err != nil {
		return nil, fmt.Errorf("ls_stas3: decoding results: %w", err)
	}

	var formulas []lookup.LookupFormula
	for _, r := range records {
		txid, err := chainhash.NewHashFromHex(r.TxID)
		if err != nil {
			continue
		}
		op := transaction.Outpoint{Txid: *txid, Index: r.Vout}
		formulas = append(formulas, lookup.LookupFormula{
			Outpoint: &op,
		})
	}

	slog.Info("ls_stas3: lookup",
		"filter", filter,
		"result_count", len(records),
	)

	if len(formulas) == 0 {
		return &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{},
		}, nil
	}

	return &lookup.LookupAnswer{
		Type:     lookup.AnswerTypeFreeform,
		Formulas: formulas,
		Result:   records,
	}, nil
}

// buildLookupFilter translates a STASQuery into a Mongo filter document.
// Empty fields are omitted so the filter only constrains explicit values.
// Extracted to allow unit-testing the query semantics independently of the
// Mongo driver.
func buildLookupFilter(q *STASQuery) bson.M {
	filter := bson.M{}
	if q.TokenID != "" {
		filter["tokenId"] = q.TokenID
	}
	if q.Address != "" {
		filter["address"] = q.Address
	}
	if q.UnspentOnly {
		filter["spent"] = false
	}
	if q.ClassHash != "" {
		filter["classHash"] = q.ClassHash
	}
	if q.ActionKind != "" {
		filter["actionKind"] = q.ActionKind
	}
	if q.FrozenOnly {
		filter["frozen"] = true
	}
	if q.SwapRequestedScriptHash != "" {
		filter["swapRequestedScriptHash"] = q.SwapRequestedScriptHash
	}
	if q.SwapRequestedPkh != "" {
		filter["swapRequestedPkh"] = q.SwapRequestedPkh
	}
	if q.TxID != "" {
		filter["txid"] = q.TxID
	}
	if q.Vout != nil {
		filter["vout"] = *q.Vout
	}
	return filter
}

func (ls *LookupService) GetDocumentation() string {
	return "STAS v3 token lookup service. " +
		"Indexes STAS v3 UTXOs and exposes filters by tokenId, address, " +
		"classHash, actionKind, swapRequestedScriptHash, swapRequestedPkh, " +
		"frozenOnly, unspentOnly, txid+vout. " +
		"Records carry the universal classHash and full action_data + " +
		"swap descriptor projections so apps can match cross-class swap " +
		"offers without further parsing."
}

func (ls *LookupService) GetMetaData() *overlay.MetaData {
	return LookupServiceMetaData()
}

func (ls *LookupService) deleteRecord(ctx context.Context, outpoint *transaction.Outpoint) error {
	filter := bson.M{
		"txid": outpoint.Txid.String(),
		"vout": outpoint.Index,
	}
	_, err := ls.col.DeleteOne(ctx, filter)
	return err
}
