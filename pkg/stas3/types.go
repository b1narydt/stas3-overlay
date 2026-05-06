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
type STASRecord struct {
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
}

// STASQuery represents a lookup query to ls_stas3.
// All fields are optional — unset fields match all entries.
type STASQuery struct {
	TokenID     string `json:"tokenId,omitempty"`
	Address     string `json:"address,omitempty"`
	UnspentOnly bool   `json:"unspentOnly,omitempty"`
}

// TopicManagerMetaData returns overlay metadata for tm_stas3.
func TopicManagerMetaData() *overlay.MetaData {
	return &overlay.MetaData{
		Name:        TopicName,
		Description: "STAS v3 token overlay — admits outputs with valid STAS v3 locking scripts",
		Version:     "1.0.0",
	}
}

// LookupServiceMetaData returns overlay metadata for ls_stas3.
func LookupServiceMetaData() *overlay.MetaData {
	return &overlay.MetaData{
		Name:        LookupServiceName,
		Description: "STAS v3 token lookup — queries token UTXOs by tokenId, address, and spent status",
		Version:     "1.0.0",
	}
}
