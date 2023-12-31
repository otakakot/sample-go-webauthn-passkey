// Code generated by ogen, DO NOT EDIT.

package api

import (
	"bytes"
	"net/http"

	"github.com/go-faster/jx"

	ht "github.com/ogen-go/ogen/http"
)

func encodeFinalizeAssertionRequest(
	req OptFinalizeAssertionRequest,
	r *http.Request,
) error {
	const contentType = "application/json"
	if !req.Set {
		// Keep request with empty body if value is not set.
		return nil
	}
	e := new(jx.Encoder)
	{
		if req.Set {
			req.Encode(e)
		}
	}
	encoded := e.Bytes()
	ht.SetBody(r, bytes.NewReader(encoded), contentType)
	return nil
}

func encodeFinalizeAttestationRequest(
	req FinalizeAttestationReq,
	r *http.Request,
) error {
	const contentType = "text/plain"
	body := req
	ht.SetBody(r, body, contentType)
	return nil
}
