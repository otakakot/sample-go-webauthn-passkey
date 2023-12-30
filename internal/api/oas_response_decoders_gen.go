// Code generated by ogen, DO NOT EDIT.

package api

import (
	"bytes"
	"io"
	"mime"
	"net/http"

	"github.com/go-faster/errors"
	"github.com/go-faster/jx"

	"github.com/ogen-go/ogen/conv"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/ogen-go/ogen/uri"
	"github.com/ogen-go/ogen/validate"
)

func decodeFinalizeAssertionResponse(resp *http.Response) (res FinalizeAssertionRes, _ error) {
	switch resp.StatusCode {
	case 200:
		// Code 200.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/json":
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return res, err
			}
			d := jx.DecodeBytes(buf)

			var response FinalizeAssertionResponse
			if err := func() error {
				if err := response.Decode(d); err != nil {
					return err
				}
				if err := d.Skip(); err != io.EOF {
					return errors.New("unexpected trailing data")
				}
				return nil
			}(); err != nil {
				err = &ogenerrors.DecodeBodyError{
					ContentType: ct,
					Body:        buf,
					Err:         err,
				}
				return res, err
			}
			return &response, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	case 500:
		// Code 500.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/json":
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return res, err
			}
			d := jx.DecodeBytes(buf)

			var response ErrorResponse
			if err := func() error {
				if err := response.Decode(d); err != nil {
					return err
				}
				if err := d.Skip(); err != io.EOF {
					return errors.New("unexpected trailing data")
				}
				return nil
			}(); err != nil {
				err = &ogenerrors.DecodeBodyError{
					ContentType: ct,
					Body:        buf,
					Err:         err,
				}
				return res, err
			}
			return &response, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	}
	return res, validate.UnexpectedStatusCode(resp.StatusCode)
}

func decodeFinalizeAttestationResponse(resp *http.Response) (res FinalizeAttestationRes, _ error) {
	switch resp.StatusCode {
	case 200:
		// Code 200.
		var wrapper FinalizeAttestationOK
		h := uri.NewHeaderDecoder(resp.Header)
		// Parse "Set-Cookie" header.
		{
			cfg := uri.HeaderParameterDecodingConfig{
				Name:    "Set-Cookie",
				Explode: false,
			}
			if err := func() error {
				if err := h.HasParam(cfg); err == nil {
					if err := h.DecodeParam(cfg, func(d uri.Decoder) error {
						var wrapperDotSetCookieVal string
						if err := func() error {
							val, err := d.DecodeValue()
							if err != nil {
								return err
							}

							c, err := conv.ToString(val)
							if err != nil {
								return err
							}

							wrapperDotSetCookieVal = c
							return nil
						}(); err != nil {
							return err
						}
						wrapper.SetCookie.SetTo(wrapperDotSetCookieVal)
						return nil
					}); err != nil {
						return err
					}
				}
				return nil
			}(); err != nil {
				return res, errors.Wrap(err, "parse Set-Cookie header")
			}
		}
		return &wrapper, nil
	case 500:
		// Code 500.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/json":
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return res, err
			}
			d := jx.DecodeBytes(buf)

			var response ErrorResponse
			if err := func() error {
				if err := response.Decode(d); err != nil {
					return err
				}
				if err := d.Skip(); err != io.EOF {
					return errors.New("unexpected trailing data")
				}
				return nil
			}(); err != nil {
				err = &ogenerrors.DecodeBodyError{
					ContentType: ct,
					Body:        buf,
					Err:         err,
				}
				return res, err
			}
			var wrapper ErrorResponseHeaders
			wrapper.Response = response
			h := uri.NewHeaderDecoder(resp.Header)
			// Parse "Set-Cookie" header.
			{
				cfg := uri.HeaderParameterDecodingConfig{
					Name:    "Set-Cookie",
					Explode: false,
				}
				if err := func() error {
					if err := h.HasParam(cfg); err == nil {
						if err := h.DecodeParam(cfg, func(d uri.Decoder) error {
							var wrapperDotSetCookieVal string
							if err := func() error {
								val, err := d.DecodeValue()
								if err != nil {
									return err
								}

								c, err := conv.ToString(val)
								if err != nil {
									return err
								}

								wrapperDotSetCookieVal = c
								return nil
							}(); err != nil {
								return err
							}
							wrapper.SetCookie.SetTo(wrapperDotSetCookieVal)
							return nil
						}); err != nil {
							return err
						}
					}
					return nil
				}(); err != nil {
					return res, errors.Wrap(err, "parse Set-Cookie header")
				}
			}
			return &wrapper, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	}
	return res, validate.UnexpectedStatusCode(resp.StatusCode)
}

func decodeInitializeAssertionResponse(resp *http.Response) (res InitializeAssertionRes, _ error) {
	switch resp.StatusCode {
	case 200:
		// Code 200.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/json":
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return res, err
			}
			d := jx.DecodeBytes(buf)

			var response InitializeAssertionResponse
			if err := func() error {
				if err := response.Decode(d); err != nil {
					return err
				}
				if err := d.Skip(); err != io.EOF {
					return errors.New("unexpected trailing data")
				}
				return nil
			}(); err != nil {
				err = &ogenerrors.DecodeBodyError{
					ContentType: ct,
					Body:        buf,
					Err:         err,
				}
				return res, err
			}
			return &response, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	case 500:
		// Code 500.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/json":
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return res, err
			}
			d := jx.DecodeBytes(buf)

			var response ErrorResponse
			if err := func() error {
				if err := response.Decode(d); err != nil {
					return err
				}
				if err := d.Skip(); err != io.EOF {
					return errors.New("unexpected trailing data")
				}
				return nil
			}(); err != nil {
				err = &ogenerrors.DecodeBodyError{
					ContentType: ct,
					Body:        buf,
					Err:         err,
				}
				return res, err
			}
			return &response, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	}
	return res, validate.UnexpectedStatusCode(resp.StatusCode)
}

func decodeInitializeAttestationResponse(resp *http.Response) (res InitializeAttestationRes, _ error) {
	switch resp.StatusCode {
	case 200:
		// Code 200.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/x-msgpack":
			reader := resp.Body
			b, err := io.ReadAll(reader)
			if err != nil {
				return res, err
			}

			response := InitializeAttestationOK{Data: bytes.NewReader(b)}
			var wrapper InitializeAttestationOKHeaders
			wrapper.Response = response
			h := uri.NewHeaderDecoder(resp.Header)
			// Parse "Set-Cookie" header.
			{
				cfg := uri.HeaderParameterDecodingConfig{
					Name:    "Set-Cookie",
					Explode: false,
				}
				if err := func() error {
					if err := h.HasParam(cfg); err == nil {
						if err := h.DecodeParam(cfg, func(d uri.Decoder) error {
							var wrapperDotSetCookieVal string
							if err := func() error {
								val, err := d.DecodeValue()
								if err != nil {
									return err
								}

								c, err := conv.ToString(val)
								if err != nil {
									return err
								}

								wrapperDotSetCookieVal = c
								return nil
							}(); err != nil {
								return err
							}
							wrapper.SetCookie.SetTo(wrapperDotSetCookieVal)
							return nil
						}); err != nil {
							return err
						}
					}
					return nil
				}(); err != nil {
					return res, errors.Wrap(err, "parse Set-Cookie header")
				}
			}
			return &wrapper, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	case 500:
		// Code 500.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/json":
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return res, err
			}
			d := jx.DecodeBytes(buf)

			var response ErrorResponse
			if err := func() error {
				if err := response.Decode(d); err != nil {
					return err
				}
				if err := d.Skip(); err != io.EOF {
					return errors.New("unexpected trailing data")
				}
				return nil
			}(); err != nil {
				err = &ogenerrors.DecodeBodyError{
					ContentType: ct,
					Body:        buf,
					Err:         err,
				}
				return res, err
			}
			return &response, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	}
	return res, validate.UnexpectedStatusCode(resp.StatusCode)
}

func decodeInitializeAttestationJSONResponse(resp *http.Response) (res InitializeAttestationJSONRes, _ error) {
	switch resp.StatusCode {
	case 200:
		// Code 200.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "text/plain":
			reader := resp.Body
			b, err := io.ReadAll(reader)
			if err != nil {
				return res, err
			}

			response := InitializeAttestationJSONOK{Data: bytes.NewReader(b)}
			var wrapper InitializeAttestationJSONOKHeaders
			wrapper.Response = response
			h := uri.NewHeaderDecoder(resp.Header)
			// Parse "Set-Cookie" header.
			{
				cfg := uri.HeaderParameterDecodingConfig{
					Name:    "Set-Cookie",
					Explode: false,
				}
				if err := func() error {
					if err := h.HasParam(cfg); err == nil {
						if err := h.DecodeParam(cfg, func(d uri.Decoder) error {
							var wrapperDotSetCookieVal string
							if err := func() error {
								val, err := d.DecodeValue()
								if err != nil {
									return err
								}

								c, err := conv.ToString(val)
								if err != nil {
									return err
								}

								wrapperDotSetCookieVal = c
								return nil
							}(); err != nil {
								return err
							}
							wrapper.SetCookie.SetTo(wrapperDotSetCookieVal)
							return nil
						}); err != nil {
							return err
						}
					}
					return nil
				}(); err != nil {
					return res, errors.Wrap(err, "parse Set-Cookie header")
				}
			}
			return &wrapper, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	case 500:
		// Code 500.
		ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return res, errors.Wrap(err, "parse media type")
		}
		switch {
		case ct == "application/json":
			buf, err := io.ReadAll(resp.Body)
			if err != nil {
				return res, err
			}
			d := jx.DecodeBytes(buf)

			var response ErrorResponse
			if err := func() error {
				if err := response.Decode(d); err != nil {
					return err
				}
				if err := d.Skip(); err != io.EOF {
					return errors.New("unexpected trailing data")
				}
				return nil
			}(); err != nil {
				err = &ogenerrors.DecodeBodyError{
					ContentType: ct,
					Body:        buf,
					Err:         err,
				}
				return res, err
			}
			return &response, nil
		default:
			return res, validate.InvalidContentType(ct)
		}
	}
	return res, validate.UnexpectedStatusCode(resp.StatusCode)
}
