// Copyright (c) 2016 BLOCKO INC.
package openassets

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/coinstack/coinstackd/coinstack/client"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil/base58"
)

func TestAssetIdCalculation(t *testing.T) {
	// test assetID calculation for issurance
	script := "76a914423b040f0b9741a6fef3f9a163ee786495b3291788ac"
	assetID, _ := calculateAssetID(decode(script))
	t.Log(assetID)
	if CalculateBase58(assetID) != "ALfkcZ8MKd112qaKixmNNQvNi1p3yAVN4r" {
		t.Error("invalid asset id calculated")
	}

}

func decode(source string) []byte {
	output, _ := hex.DecodeString(source)
	return output
}

func TestParsingMarkerOutput(t *testing.T) {
	// test parsing marker output
	_, ok := ParseMarkerOutput(&wire.TxOut{
		Value:    0,
		PkScript: decode("6a3445572043207175696572652061204420627574204420646f65736e74207175696572652043206e6f7720697320737472616e6765"),
	}, 0, 1)
	if ok {
		t.Error("failed to recognize marker output (false positive)")
	}

	_, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("76a914d717483b5554670550f8e79a3b958d294ecf806088ac"),
	}, 0, 1)
	if ok {
		t.Error("failed to recognize marker output (false positive)")
	}

	marker, ok := ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a224f41010001011b753d68747470733a2f2f6370722e736d2f63463557584459643642"),
	}, 0, 2)
	if !ok {
		t.Error("failed to recognize marker output (false negative)")
	}
	if len(marker.Quantities) != 2 || marker.Quantities[1] != 1 {
		t.Error("wrong number of quantities")
	}

	// https://watch.cloudwallet.io/tx/34cc9c98ccf4d675b04a44d7d9be4278a389546ae21331ffa14e0bcefdb63df3
	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a084f41010001c70300"),
	}, 1, 2)
	if !ok {
		t.Error("failed to recognize marker output (false negative)")
	}
	if len(marker.Quantities) != 2 || marker.Quantities[0] != 455 {
		t.Error("wrong number of quantities")
	}

	// parse some complex marker output
	// https://watch.cloudwallet.io/tx/fb58ea9d6e3e5730d137337450557aa1a4282c9f2426bc80b6109d62310ff1d0
	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a0a4f41010002c007960100"),
	}, 1, 3)
	if !ok {
		t.Error("failed to recognize marker output (false negative)")
	}
	if len(marker.Quantities) != 3 || marker.Quantities[0] != 960 || marker.Quantities[2] != 150 || marker.Quantities[1] != 0 {
		t.Error("wrong number of quantities")
	}

	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a104f410100018080808080808080800200"),
	}, 0, 2)
	if !ok {
		t.Error("failed to recognize marker output (false negative)")
	}

	// tx 56fa88fbe753a67b53d898206dc678bd462543424654dd26b5224dc8f8726b7c
	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a174f4101000101753d687474703a2f2f7265642e70696c6c"),
	}, 1, 2)
	if !ok {
		t.Fatal("failed to recognize marker output (false negative)")
	}
	for _, quantity := range marker.Quantities {
		t.Log(quantity)
	}

	// test TX 1cbcd3bdb11e32078f845126907b5be3503bc3c3d28706571d9abf8e4b6fa1c7
	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a094f41010002ac02ee1e"),
	}, 1, 3)
	if !ok {
		t.Fatal("failed to recognize marker output (false negative)")
	}
	for _, quantity := range marker.Quantities {
		t.Log(quantity)
	}

	// tx d259d2853b6ff2fa013ddd5e4072470d5a49e0e7c055b98114d23388db3fbfd0
	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a224f410100019a21753d68747470733a2f2f6370722e736d2f416545476877707a7833"),
	}, 1, 2)
	if !ok {
		t.Fatal("failed to recognize marker output (false negative)")
	}
	t.Log(len(marker.Quantities))
	for _, quantity := range marker.Quantities {
		t.Log(quantity)
	}

	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a054f4101000111753d687474703a2f2f7265642e70696c6c"),
	}, 1, 3)
	if ok {
		t.Error("failed to recognize marker output (false positive)")
	}

	// try marker with zero quanties
	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a054f4101000011753d687474703a2f2f7265642e70696c6c"),
	}, 1, 2)
	if !ok {
		t.Fatal("failed to recognize marker output (false negative)")
	}
	if len(marker.Quantities) != 2 {
		t.Log(len(marker.Quantities))
		t.Fatal("failed to parse correct number of quantities")
	}

	marker, ok = ParseMarkerOutput(&wire.TxOut{
		PkScript: decode("6a0a4f41010002b817c86500"),
	}, 0, 4)
	if !ok {
		t.Fatal("failed to recognize marker output (false negative)")
	}
	for _, quantity := range marker.Quantities {
		t.Log(quantity)
	}

	// if len(marker.Quantities) != 2 {
	// 	t.Log(len(marker.Quantities))
	// 	t.Fatal("failed to parse correct number of quantities")
	// }

}

func decodeBase58(source string) []byte {
	result, _, _ := base58.CheckDecode(source)
	return result
}

func convertCoinstackTx(tx client.Transaction) (*wire.MsgTx, []*Meta) {
	outputTx := wire.NewMsgTx()
	inputMeta := make([]*Meta, len(tx.Inputs))
	for i, input := range tx.Inputs {
		outputTx.AddTxIn(&wire.TxIn{
			SignatureScript: decode(input.Script),
		})

		if input.Metadata == nil || input.Metadata.OpenAssets.OutputType == "UNCOLORED" {
			inputMeta[i] = &Meta{
				OutputType: MetaUncolored,
				Script:     decode(input.Script),
			}
		} else if input.Metadata.OpenAssets.OutputType == "ISSUANCE" {
			inputMeta[i] = &Meta{
				OutputType: MetaIssuance,
				AssetID:    decodeBase58(input.Metadata.OpenAssets.AssetID),
				Quantity:   input.Metadata.OpenAssets.Quantity,
				Script:     decode(input.Script),
			}
		} else if input.Metadata.OpenAssets.OutputType == "TRANSFER" {
			inputMeta[i] = &Meta{
				OutputType: MetaTransfer,
				AssetID:    decodeBase58(input.Metadata.OpenAssets.AssetID),
				Quantity:   input.Metadata.OpenAssets.Quantity,
				Script:     decode(input.Script),
			}
		}
	}
	for range tx.Outputs {
		outputTx.AddTxOut(&wire.TxOut{})
	}

	return outputTx, inputMeta
}

func TestOrderBasedColoring(t *testing.T) {
	var ok, isOA bool
	var marker *Marker

	// simple issuance tx
	tx, meta := convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 0,
				Script:      "76a914d717483b5554670550f8e79a3b958d294ecf806088ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
		},
	})

	testMarker := Marker{
		MarkerIndex:  1,
		Quantities:   []uint64{3, 0},
		MajorVersion: 1,
		MinorVersion: 0,
	}

	// assign quantities to outputs based on input information
	outputMeta, isOA := AssignQuantities(tx, meta, &testMarker)
	if !isOA {
		t.Fatalf("failed to assign quantities")
	}

	if outputMeta[0].OutputType != MetaIssuance ||
		outputMeta[0].Quantity != 3 ||
		!bytes.Equal(outputMeta[0].AssetID, decodeBase58("AJS39eYsPGYo3S8L73xWGv8DwPHT4LYp8B")) {
		t.Log(outputMeta[0])
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[1].OutputType != MetaMarker {
		t.Error("open asset metadata not properly assigned")
	}

	for _, output := range outputMeta {
		t.Log(output)
	}

	// simple transfer tx
	tx, meta = convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 0,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "ISSUANCE",
						AssetID:    "1d27fd8fac0cda221b3fccc6ecc1fc46cd9178d0",
						Quantity:   3,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
		},
	})

	testMarker = Marker{
		MarkerIndex:  0,
		Quantities:   []uint64{0, 3},
		MajorVersion: 1,
		MinorVersion: 0,
	}

	// assign quantities to outputs based on input information
	outputMeta, isOA = AssignQuantities(tx, meta, &testMarker)
	if !isOA {
		t.Fatal("failed to assign quantities")
	}

	if outputMeta[0].OutputType != MetaMarker {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[1].OutputType != MetaTransfer ||
		outputMeta[1].Quantity != 3 ||
		!bytes.Equal(outputMeta[1].AssetID, decodeBase58("1d27fd8fac0cda221b3fccc6ecc1fc46cd9178d0")) {
		t.Error("open asset metadata not properly assigned")
	}

	for _, output := range outputMeta {
		t.Log(output)
	}

	// issuance and transfer
	tx, meta = convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 0,
				Script:      "76a914d717483b5554670550f8e79a3b958d294ecf806088ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "ALfkcZ8MKd112qaKixmNNQvNi1p3yAVN4r", // a1
						Quantity:   3,
					},
				},
			},
			{
				OutputIndex: 0,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "ALfkcZ8MKd112qaKixmNNQvNi1p3yAVN4r", // a1
						Quantity:   2,
					},
				},
			},
			{
				OutputIndex: 0,
				Script:      "76a914d717483b5554670550f8e79a3b958d294ecf806088ac",
			},
			{
				OutputIndex: 0,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "ALfkcZ8MKd112qaKixmNNQvNi1p3yAVN4r",
						Quantity:   5,
					},
				},
			},
			{
				OutputIndex: 0,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "ALfkcZ8MKd112qaKixmNNQvNi1p3yAVN4r",
						Quantity:   3,
					},
				},
			},
			{
				OutputIndex: 0,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "AJS39eYsPGYo3S8L73xWGv8DwPHT4LYp8B", // a2
						Quantity:   9,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
			{
				Index: 2,
			},
			{
				Index: 3,
			},
			{
				Index: 4,
			},
			{
				Index: 5,
			},
			{
				Index: 6,
			},
			{
				Index: 7,
			},
			{
				Index: 8,
			},
			{
				Index: 9,
			},
		},
	})
	testMarker = Marker{
		MarkerIndex:  2,
		Quantities:   []uint64{0, 10, 0, 6, 0, 7, 3, 0, 1},
		MajorVersion: 1,
		MinorVersion: 0,
	}
	outputMeta, isOA = AssignQuantities(tx, meta, &testMarker)
	if !isOA {
		t.Fatal("failed to assign quantities")
	}

	if outputMeta[0].OutputType != MetaUncolored ||
		outputMeta[0].Quantity != 0 ||
		outputMeta[0].AssetID != nil {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[1].OutputType != MetaIssuance ||
		outputMeta[1].Quantity != 10 ||
		!bytes.Equal(outputMeta[1].AssetID, decodeBase58("AJS39eYsPGYo3S8L73xWGv8DwPHT4LYp8B")) {
		t.Log(outputMeta[1])
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[2].OutputType != MetaMarker {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[3].OutputType != MetaTransfer ||
		outputMeta[3].Quantity != 6 ||
		!bytes.Equal(outputMeta[3].AssetID, decodeBase58("ALfkcZ8MKd112qaKixmNNQvNi1p3yAVN4r")) {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[4].OutputType != MetaUncolored ||
		outputMeta[4].Quantity != 0 ||
		outputMeta[4].AssetID != nil {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[5].OutputType != MetaTransfer ||
		outputMeta[5].Quantity != 7 ||
		!bytes.Equal(outputMeta[5].AssetID, decodeBase58("ALfkcZ8MKd112qaKixmNNQvNi1p3yAVN4r")) {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[6].OutputType != MetaTransfer ||
		outputMeta[6].Quantity != 3 ||
		!bytes.Equal(outputMeta[6].AssetID, decodeBase58("AJS39eYsPGYo3S8L73xWGv8DwPHT4LYp8B")) {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[9].OutputType != MetaUncolored ||
		outputMeta[9].Quantity != 0 ||
		outputMeta[9].AssetID != nil {
		t.Log(outputMeta[9])
		t.Error("open asset metadata not properly assigned")
	}

	for _, output := range outputMeta {
		t.Log(output)
		if output.OutputType == MetaMarker {
			t.Log(output.MajorVersion)
			t.Log(output.MinorVersion)
		}
	}

	// test TX 56fa88fbe753a67b53d898206dc678bd462543424654dd26b5224dc8f8726b7c
	tx, meta = convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 0,
				Script:      "76a914af8ba2f6cef60992f018e20d1ebd9c7118fa625588ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
			{
				Index: 2,
			},
		},
	})

	marker, ok = ParseMarkerOutput(&wire.TxOut{
		Value:    0,
		PkScript: decode("6a174f4101000101753d687474703a2f2f7265642e70696c6c"),
	}, 1, 2)
	if !ok {
		t.Fatal("failed to parse marker outputs")
	}
	_, isOA = AssignQuantities(tx, meta, marker)
	if !isOA {
		t.Fatal("failed to assign quantities")
	}
	// test TX d259d2853b6ff2fa013ddd5e4072470d5a49e0e7c055b98114d23388db3fbfd0
	tx, meta = convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 0,
				Script:      "76a914b2a2de394ce286509c8e4c30dcd157df001cdf7388ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
			{
				Index: 2,
			},
		},
	})
	marker, _ = ParseMarkerOutput(&wire.TxOut{
		Value:    0,
		PkScript: decode("6a224f410100019a21753d68747470733a2f2f6370722e736d2f416545476877707a7833"),
	}, 1, 2)
	_, isOA = AssignQuantities(tx, meta, marker)
	if !isOA {
		t.Fatal("failed to assign quantities")
	}

	// test TX 1cbcd3bdb11e32078f845126907b5be3503bc3c3d28706571d9abf8e4b6fa1c7
	tx, meta = convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 0,
				Script:      "76a914b2a2de394ce286509c8e4c30dcd157df001cdf7388ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
			{
				OutputIndex: 0,
				Script:      "76a914b2a2de394ce286509c8e4c30dcd157df001cdf7388ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
			{
				Index: 1,
			},
		},
	})
	marker, _ = ParseMarkerOutput(&wire.TxOut{
		Value:    0,
		PkScript: decode("6a094f41010002ac02ee1e"),
	}, 0, 3)
	for _, quantity := range marker.Quantities {
		t.Log(quantity)
	}
	_, isOA = AssignQuantities(tx, meta, marker)
	if isOA {
		// no input asset quantity for transfer outputs
		t.Fatal("non-standard OA tx detection failed (false negative)")
	}

	// test TX 77a6bbc65aa0326015835a3813778df4a037c15fb655e8678f234d8e2fc7439c
	tx, meta = convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 0,
				Script:      "76a914d717483b5554670550f8e79a3b958d294ecf806088ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
			{
				Index: 2,
			},
			{
				Index: 3,
			},
		},
	})

	marker, ok = ParseMarkerOutput(&wire.TxOut{
		Value:    0,
		PkScript: decode("6a224f41010001011b753d68747470733a2f2f6370722e736d2f63463557584459643642"),
	}, 1, 3)

	if !ok {
		t.Fatal("failed to parse marker outputs")
	}
	outputMeta, isOA = AssignQuantities(tx, meta, marker)
	if !isOA {
		t.Fatal("failed to assign quantities")
	}
	if outputMeta[2].OutputType != MetaUncolored ||
		outputMeta[2].Quantity != 0 ||
		outputMeta[2].AssetID != nil {
		t.Error("open asset metadata not properly assigned")
	}

	if outputMeta[3].OutputType != MetaUncolored ||
		outputMeta[3].Quantity != 0 ||
		outputMeta[3].AssetID != nil {
		t.Error("open asset metadata not properly assigned")
	}

	// test TX 4dd1b7130045f84e7dd75a03dc802063f76687812cf877dacff2a645a1b0991b

	// test TX f7f036b2dc9be9a7cf3b6a2e2bdc82205ad46ff5403b1ca91f2fcbb4a8aa7f22
	tx, meta = convertCoinstackTx(client.Transaction{
		Inputs: []client.Input{
			{
				OutputIndex: 1,
				Script:      "76a914db491629a8e24cf0b22833c0b2521666f689815688ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
			{
				OutputIndex: 1,
				Script:      "76a914db491629a8e24cf0b22833c0b2521666f689815688ac",
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "UNCOLORED",
						AssetID:    "",
						Quantity:   0,
					},
				},
			},
			{
				OutputIndex: 1,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "Af59wop4VJjXk2DAzoX9scAUCcAsghPHFX",
						Quantity:   1000,
					},
				},
			},

			{
				OutputIndex: 1,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "Af59wop4VJjXk2DAzoX9scAUCcAsghPHFX",
						Quantity:   1000,
					},
				},
			},
			{
				OutputIndex: 1,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "Af59wop4VJjXk2DAzoX9scAUCcAsghPHFX",
						Quantity:   1000,
					},
				},
			},
			{
				OutputIndex: 1,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "AR2qJ7tJAdRWJSp1D6qKQyRmKfUL79GN13",
						Quantity:   1300,
					},
				},
			},
			{
				OutputIndex: 1,
				Metadata: &client.Metadata{
					OpenAssets: &client.OpenAssetsMeta{
						OutputType: "TRANSFER",
						AssetID:    "AR2qJ7tJAdRWJSp1D6qKQyRmKfUL79GN13",
						Quantity:   11700,
					},
				},
			},
		},
		Outputs: []client.Output{
			{
				Index: 0,
			},
			{
				Index: 1,
			},
			{
				Index: 2,
			},
			{
				Index: 3,
			},
		},
	})
	marker, ok = ParseMarkerOutput(&wire.TxOut{
		Value:    0,
		PkScript: decode("6a0a4f41010002b817c86500"),
	}, 0, 4)
	if !ok {
		t.Fatal("failed to parse marker outputs")
	}
	_, isOA = AssignQuantities(tx, meta, marker)
	if !isOA {
		t.Fatal("failed to assign quantities")
	}
}
