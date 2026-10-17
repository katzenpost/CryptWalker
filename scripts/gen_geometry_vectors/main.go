// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Writes testdata/sphinx_geometry.json: Sphinx geometries built by katzenpost's
// core/sphinx/geo, each with its CBOR encoding, its canonical encoding and Hash().
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type vector struct {
	Scheme                   string        `json:"scheme"`
	IsKEM                    bool          `json:"is_kem"`
	UserForwardPayloadLength int           `json:"user_forward_payload_length"`
	WithSURB                 bool          `json:"with_surb"`
	NrHops                   int           `json:"nr_hops"`
	Geometry                 *geo.Geometry `json:"geometry"`
	CBOR                     string        `json:"cbor"`
	CanonicalCBOR            string        `json:"canonical_cbor"`
	Hash                     string        `json:"hash"`
}

// Schemes whose names Cryptlib's NIKE and KEM registries resolve.
var nikes = []string{"X25519"}
var kems = []string{"MLKEM768"}

func main() {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	var out []vector
	add := func(name string, isKEM bool, payload int, withSURB bool, hops int) {
		var g *geo.Geometry
		if isKEM {
			s := kemschemes.ByName(name)
			if s == nil {
				panic("unknown KEM " + name)
			}
			g = geo.KEMGeometryFromUserForwardPayloadLength(s, payload, withSURB, hops)
		} else {
			s := nikeschemes.ByName(name)
			if s == nil {
				panic("unknown NIKE " + name)
			}
			g = geo.GeometryFromUserForwardPayloadLength(s, payload, withSURB, hops)
		}
		if err := g.Validate(); err != nil {
			panic(err)
		}
		canonical, err := enc.Marshal(g)
		if err != nil {
			panic(err)
		}
		blob, err := cbor.Marshal(g)
		if err != nil {
			panic(err)
		}
		out = append(out, vector{name, isKEM, payload, withSURB, hops, g,
			hex.EncodeToString(blob), hex.EncodeToString(canonical), hex.EncodeToString(g.Hash())})
	}
	for _, payload := range []int{0, 2000, 30000} {
		for _, withSURB := range []bool{false, true} {
			for _, hops := range []int{1, 5, 20} {
				for _, n := range nikes {
					add(n, false, payload, withSURB, hops)
				}
				for _, k := range kems {
					add(k, true, payload, withSURB, hops)
				}
			}
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
	_ = os.Stdout.Sync()
}
