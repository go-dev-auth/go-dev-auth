package godevauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Secret rotation and ciphertext migration.
//
// Config.Secret derives the key that encrypts values at rest. Rotating
// it is a three-step deploy (see Config.PreviousSecrets); this file is
// the middle step — rewriting stored values under the new key so the
// old secret can be dropped.
//
// The same pass also migrates the on-disk format. Values written before
// ciphertexts were bound to their storage location (crypto formats v0
// and v1) are rewritten as v2, which authenticates the model, record id
// and field name alongside the value. Once a pass reports nothing left
// to rewrite, Config.RequireBoundCiphertexts can be set and the unbound
// formats stop being accepted at all.
//
// It is a batch operation, not something the request path does. Lazily
// re-encrypting on read would be tidier but would never finish: a user
// who does not sign in for a year keeps a value under the old key for a
// year, and the operator has no way to know when it is safe to remove
// the old secret. A helper that reports how much is left answers that
// question.

// reencryptBatchSize is how many records a pass holds in memory at
// once. The pass walks the table in id order rather than loading it
// whole: an instance with a million accounts must not need a million
// rows of resident memory to rotate a secret.
const reencryptBatchSize = 200

// ReencryptResult reports what a re-encryption pass did.
type ReencryptResult struct {
	// Scanned is how many encrypted values were examined.
	Scanned int
	// Rewritten is how many were re-encrypted under the current key.
	Rewritten int
	// Unreadable is how many could not be decrypted by any configured
	// key. These are the values a rotation has already stranded: they
	// need the missing secret added to Config.PreviousSecrets, or the
	// records themselves reset (a stranded TOTP secret means that user
	// must re-enrol).
	Unreadable int
	// Skipped is how many were left alone because the stored value
	// changed between the read and the write — a concurrent
	// /refresh-token, a backup-code regeneration, a 2FA re-enrolment.
	// The newer value is already under the current key (the writer used
	// this instance's keyring), so a skip is not work lost; it only
	// means this pass did not have to do it. A non-zero count is
	// expected on a busy instance and is not an error.
	Skipped int
	// Failed is how many could not be written back because the storage
	// call returned an error. The pass continues past them and reports
	// the errors; run it again once the cause is fixed.
	Failed int
}

func (r *ReencryptResult) add(o ReencryptResult) {
	r.Scanned += o.Scanned
	r.Rewritten += o.Rewritten
	r.Unreadable += o.Unreadable
	r.Skipped += o.Skipped
	r.Failed += o.Failed
}

// Done reports whether nothing is left to do: every value examined is
// already under the current key in the current format, nothing was
// stranded, and nothing failed. When a pass is Done, Config.Secret's
// predecessors can be dropped from Config.PreviousSecrets and
// Config.RequireBoundCiphertexts can be turned on.
//
// A pass with Skipped > 0 is not Done — those rows were rewritten by
// somebody else mid-pass and the next pass will confirm them.
func (r ReencryptResult) Done() bool {
	return r.Rewritten == 0 && r.Unreadable == 0 && r.Skipped == 0 && r.Failed == 0
}

// SecretRotator is implemented by plugins that store values encrypted
// with the instance secret. Auth.ReencryptSecrets calls it so a
// rotation covers plugin-owned tables (2FA secrets, JWT signing keys)
// without the core needing to know they exist.
type SecretRotator interface {
	// ReencryptSecrets rewrites this plugin's encrypted values under
	// the current key. It must be idempotent: values already under the
	// current key are counted and left alone.
	ReencryptSecrets(ctx context.Context) (ReencryptResult, error)
}

// ReencryptSecrets rewrites every value this instance holds encrypted —
// OAuth tokens in the account table, plus whatever each plugin
// implementing SecretRotator owns — under the current Config.Secret and
// in the current on-disk format.
//
// Run it after deploying with the new secret in Secret and the old one
// in PreviousSecrets. When a pass reports Done, nothing is left under
// an old key or in an unbound format: PreviousSecrets can be emptied
// and Config.RequireBoundCiphertexts set on the next deploy.
//
// It is safe to run on a live instance:
//
//   - Each field is rewritten with a compare-and-set on the ciphertext
//     it was read from, so a concurrent write (a token refresh, a
//     backup-code regeneration) is never reverted. The row is counted
//     in Skipped and left as the concurrent writer left it.
//   - Records are walked in batches of reencryptBatchSize in id order,
//     not loaded whole.
//   - Both the old and the new key are readable throughout.
//
// It is not transactional across records, so an interrupted run simply
// leaves work for the next one. A failure in one plugin's rotator does
// not stop the others: every rotator runs, and the errors are joined
// into the returned error.
func (a *Auth) ReencryptSecrets(ctx context.Context) (ReencryptResult, error) {
	var total ReencryptResult
	var errs []error

	accounts, err := a.reencryptAccountTokens(ctx)
	total.add(accounts)
	if err != nil {
		errs = append(errs, err)
	}

	for _, p := range a.config.Plugins {
		rotator, ok := p.(SecretRotator)
		if !ok {
			continue
		}
		res, err := rotator.ReencryptSecrets(ctx)
		total.add(res)
		if err != nil {
			// Do not abandon the remaining plugins: one transient
			// storage error must not leave the jwt signing key
			// un-migrated because the two-factor table happened to be
			// listed first.
			errs = append(errs, fmt.Errorf("go-dev-auth: re-encrypting %s secrets: %w", p.ID(), err))
		}
	}
	return total, errors.Join(errs...)
}

// reencryptAccountTokens rewrites the "enc:"-prefixed OAuth tokens on
// the account table.
func (a *Auth) reencryptAccountTokens(ctx context.Context) (ReencryptResult, error) {
	return a.reencryptFields(ctx, storage.ModelAccount, encPrefix,
		[]string{"accessToken", "refreshToken", "idToken"})
}

// ReencryptRecords is a helper for plugins implementing SecretRotator:
// it walks every record of a model and re-encrypts the named fields
// under the current key, binding each value to its model, record id and
// field name.
//
// The fields must hold raw keyring ciphertext (no "enc:" prefix). An
// empty field is skipped; a field no configured key can read is counted
// as unreadable and logged, so one stranded row does not abort the
// migration of the rest. Each write is a compare-and-set on the value
// that was read, so a concurrent update is skipped rather than
// clobbered.
func (a *Auth) ReencryptRecords(ctx context.Context, model string, fields ...string) (ReencryptResult, error) {
	return a.reencryptFields(ctx, model, "", fields)
}

// reencryptFields is the shared body of the account-token and
// plugin-record passes. prefix is the marker the stored value carries
// in front of the ciphertext ("enc:" for account tokens, empty
// elsewhere).
func (a *Auth) reencryptFields(ctx context.Context, model, prefix string, fields []string) (ReencryptResult, error) {
	var res ReencryptResult
	var errs []error

	lastID := ""
	for {
		var where []storage.Where
		if lastID != "" {
			where = []storage.Where{{Field: "id", Operator: storage.OpGt, Value: lastID}}
		}
		records, err := a.config.Database.FindMany(ctx, model, where, &storage.FindOptions{
			Limit:  reencryptBatchSize,
			SortBy: &storage.SortBy{Field: "id", Direction: "asc"},
		})
		if err != nil {
			errs = append(errs, err)
			break
		}
		if len(records) == 0 {
			break
		}
		batchLast := lastID
		for _, rec := range records {
			id, _ := rec["id"].(string)
			if id > batchLast {
				batchLast = id
			}
			if id == "" {
				// Nothing to bind a ciphertext to and nothing to
				// compare-and-set against. Report it rather than
				// rewrite something that cannot be addressed.
				errs = append(errs, fmt.Errorf("go-dev-auth: %s has a record with no id; cannot re-encrypt it", model))
				res.Failed++
				continue
			}
			for _, field := range fields {
				one, err := a.reencryptField(ctx, model, prefix, id, field, rec)
				res.add(one)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
		if batchLast == lastID {
			// The cursor did not advance (every record in the batch
			// sorted at or before the previous page). Stop rather than
			// spin.
			break
		}
		lastID = batchLast
		if len(records) < reencryptBatchSize {
			break
		}
	}
	return res, errors.Join(errs...)
}

// reencryptField re-encrypts one field of one record. It returns the
// counts for that single field so the caller can accumulate them.
func (a *Auth) reencryptField(ctx context.Context, model, prefix, id, field string, rec map[string]any) (ReencryptResult, error) {
	var res ReencryptResult

	stored, _ := rec[field].(string)
	body := stored
	if prefix != "" {
		if !hasEncPrefix(stored) {
			return res, nil // not encrypted at rest
		}
		body = stored[len(prefix):]
	} else if stored == "" {
		return res, nil
	}
	res.Scanned++
	if !a.keyring.NeedsReencryption(body) {
		return res, nil
	}

	b := crypto.Binding{Model: model, Record: id, Field: field}
	plain, err := a.keyring.Decrypt(b, body)
	if err != nil {
		res.Unreadable++
		switch {
		case errors.Is(err, crypto.ErrUnboundCiphertext):
			// Self-inflicted and easy to undo: the operator turned the
			// switch on before the migration finished. Say so, rather
			// than sending them looking for a missing secret.
			a.logger.Error("go-dev-auth: cannot migrate a value written before ciphertexts were bound to their "+
				"storage location, because Config.RequireBoundCiphertexts is set; clear it, run ReencryptSecrets "+
				"until it reports Done, then set it again",
				"model", model, "id", id, "field", field)
		default:
			a.logger.Error("go-dev-auth: stored value cannot be decrypted by any configured secret",
				"model", model, "id", id, "field", field, "err", err)
		}
		return res, nil
	}
	rewritten, err := a.keyring.Encrypt(b, plain)
	if err != nil {
		res.Failed++
		return res, fmt.Errorf("go-dev-auth: re-encrypting %s.%s of %s: %w", model, field, id, err)
	}

	// Compare-and-set on the ciphertext this pass read. Without the
	// predicate a write that landed between the read and this update —
	// a refreshed OAuth token, a freshly regenerated set of backup
	// codes — would be silently reverted to the value the pass is
	// holding. Reverting backup codes after a compromise re-enables
	// codes the attacker has.
	n, err := a.config.Database.UpdateMany(ctx, model,
		[]storage.Where{storage.W("id", id), storage.W(field, stored)},
		map[string]any{field: prefix + rewritten})
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			res.Skipped++ // deleted mid-pass; nothing to migrate
			return res, nil
		}
		res.Failed++
		return res, fmt.Errorf("go-dev-auth: writing back %s.%s of %s: %w", model, field, id, err)
	}
	if n == 0 {
		// Someone else wrote this row first. Their value was encrypted
		// by a live instance, so it is already current; leave it.
		res.Skipped++
		a.logger.Info("go-dev-auth: skipped re-encrypting a value that changed during the pass",
			"model", model, "id", id, "field", field)
		return res, nil
	}
	res.Rewritten++
	return res, nil
}
