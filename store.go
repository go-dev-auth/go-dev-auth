package godevauth

import (
	"context"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// store is the typed layer over the raw storage.Adapter: it owns ID
// generation, timestamps, model<->record conversion and the database
// hooks, so handlers work with domain types instead of maps.
type store struct {
	auth *Auth
	base storage.Adapter
}

// transaction runs fn inside a database transaction when the adapter
// supports one, so a multi-statement write either lands whole or not at
// all. When the adapter has no transaction support fn runs directly, and
// the caller is responsible for compensation. The store passed to fn is
// bound to the transaction, so its writes participate in it.
func (st *store) transaction(ctx context.Context, fn func(tx *store) error) error {
	tr, ok := st.base.(storage.Transactor)
	if !ok {
		return fn(st)
	}
	return tr.Transaction(ctx, func(txBase storage.Adapter) error {
		return fn(&store{auth: st.auth, base: txBase})
	})
}

func (st *store) generateID(model string) string {
	if gen := st.auth.config.Advanced.GenerateID; gen != nil {
		return gen(model)
	}
	return crypto.GenerateID(32)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ---- users ----

func (st *store) CreateUser(ctx context.Context, u *storage.User) (*storage.User, error) {
	now := time.Now().UTC()
	if u.ID == "" {
		u.ID = st.generateID(storage.ModelUser)
	}
	u.Email = normalizeEmail(u.Email)
	u.CreatedAt = now
	u.UpdatedAt = now
	rec := storage.UserToMap(u)
	if h := st.auth.config.DatabaseHooks.User.BeforeCreate; h != nil {
		if err := h(ctx, rec); err != nil {
			return nil, err
		}
	}
	out, err := st.base.Create(ctx, storage.ModelUser, rec)
	if err != nil {
		return nil, err
	}
	if h := st.auth.config.DatabaseHooks.User.AfterCreate; h != nil {
		if err := h(ctx, out); err != nil {
			return nil, err
		}
	}
	return storage.UserFromMap(out), nil
}

func (st *store) FindUserByID(ctx context.Context, id string) (*storage.User, error) {
	rec, err := st.base.FindOne(ctx, storage.ModelUser, []storage.Where{storage.W("id", id)})
	if err != nil {
		return nil, err
	}
	return storage.UserFromMap(rec), nil
}

func (st *store) FindUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	rec, err := st.base.FindOne(ctx, storage.ModelUser,
		[]storage.Where{storage.W("email", normalizeEmail(email))})
	if err != nil {
		return nil, err
	}
	return storage.UserFromMap(rec), nil
}

func (st *store) UpdateUser(ctx context.Context, id string, update map[string]any) (*storage.User, error) {
	update["updatedAt"] = time.Now().UTC()
	if h := st.auth.config.DatabaseHooks.User.BeforeUpdate; h != nil {
		if err := h(ctx, update); err != nil {
			return nil, err
		}
	}
	rec, err := st.base.Update(ctx, storage.ModelUser, []storage.Where{storage.W("id", id)}, update)
	if err != nil {
		return nil, err
	}
	if h := st.auth.config.DatabaseHooks.User.AfterUpdate; h != nil {
		if err := h(ctx, rec); err != nil {
			return nil, err
		}
	}
	return storage.UserFromMap(rec), nil
}

func (st *store) DeleteUser(ctx context.Context, id string) error {
	// One transaction: a partial delete would leave a user without a
	// credential, or sessions and accounts orphaned from a deleted
	// user. Plugin-owned rows are removed by the database foreign-key
	// cascade (or the plugin-cascade fallback for adapters without one,
	// see deleteUserPluginData).
	return st.transaction(ctx, func(tx *store) error {
		if _, err := tx.base.DeleteMany(ctx, storage.ModelSession, []storage.Where{storage.W("userId", id)}); err != nil {
			return err
		}
		if _, err := tx.base.DeleteMany(ctx, storage.ModelAccount, []storage.Where{storage.W("userId", id)}); err != nil {
			return err
		}
		if err := tx.auth.deleteUserPluginData(ctx, tx.base, id); err != nil {
			return err
		}
		return tx.base.Delete(ctx, storage.ModelUser, []storage.Where{storage.W("id", id)})
	})
}

// ---- sessions ----

func (st *store) CreateSession(ctx context.Context, s *storage.Session) (*storage.Session, error) {
	now := time.Now().UTC()
	if s.ID == "" {
		s.ID = st.generateID(storage.ModelSession)
	}
	if s.Token == "" {
		s.Token = crypto.GenerateToken(32)
	}
	s.CreatedAt = now
	s.UpdatedAt = now
	rec := storage.SessionToMap(s)
	if h := st.auth.config.DatabaseHooks.Session.BeforeCreate; h != nil {
		if err := h(ctx, rec); err != nil {
			return nil, err
		}
	}
	out, err := st.base.Create(ctx, storage.ModelSession, rec)
	if err != nil {
		return nil, err
	}
	if h := st.auth.config.DatabaseHooks.Session.AfterCreate; h != nil {
		if err := h(ctx, out); err != nil {
			return nil, err
		}
	}
	return storage.SessionFromMap(out), nil
}

func (st *store) FindSessionByToken(ctx context.Context, token string) (*storage.Session, error) {
	rec, err := st.base.FindOne(ctx, storage.ModelSession, []storage.Where{storage.W("token", token)})
	if err != nil {
		return nil, err
	}
	return storage.SessionFromMap(rec), nil
}

func (st *store) UpdateSession(ctx context.Context, token string, update map[string]any) (*storage.Session, error) {
	update["updatedAt"] = time.Now().UTC()
	rec, err := st.base.Update(ctx, storage.ModelSession, []storage.Where{storage.W("token", token)}, update)
	if err != nil {
		return nil, err
	}
	return storage.SessionFromMap(rec), nil
}

func (st *store) DeleteSessionByToken(ctx context.Context, token string) error {
	return st.base.Delete(ctx, storage.ModelSession, []storage.Where{storage.W("token", token)})
}

func (st *store) FindSessionByID(ctx context.Context, id string) (*storage.Session, error) {
	rec, err := st.base.FindOne(ctx, storage.ModelSession, []storage.Where{storage.W("id", id)})
	if err != nil {
		return nil, err
	}
	return storage.SessionFromMap(rec), nil
}

func (st *store) DeleteSessionByID(ctx context.Context, id string) error {
	return st.base.Delete(ctx, storage.ModelSession, []storage.Where{storage.W("id", id)})
}

func (st *store) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := st.base.DeleteMany(ctx, storage.ModelSession, []storage.Where{storage.W("userId", userID)})
	return err
}

func (st *store) ListUserSessions(ctx context.Context, userID string) ([]*storage.Session, error) {
	recs, err := st.base.FindMany(ctx, storage.ModelSession,
		[]storage.Where{storage.W("userId", userID)},
		&storage.FindOptions{SortBy: &storage.SortBy{Field: "createdAt", Direction: "desc"}})
	if err != nil {
		return nil, err
	}
	out := make([]*storage.Session, 0, len(recs))
	for _, rec := range recs {
		out = append(out, storage.SessionFromMap(rec))
	}
	return out, nil
}

// ---- accounts ----

func (st *store) CreateAccount(ctx context.Context, acc *storage.Account) (*storage.Account, error) {
	now := time.Now().UTC()
	if acc.ID == "" {
		acc.ID = st.generateID(storage.ModelAccount)
	}
	acc.CreatedAt = now
	acc.UpdatedAt = now
	rec := storage.AccountToMap(acc)
	if h := st.auth.config.DatabaseHooks.Account.BeforeCreate; h != nil {
		if err := h(ctx, rec); err != nil {
			return nil, err
		}
	}
	out, err := st.base.Create(ctx, storage.ModelAccount, rec)
	if err != nil {
		return nil, err
	}
	if h := st.auth.config.DatabaseHooks.Account.AfterCreate; h != nil {
		if err := h(ctx, out); err != nil {
			return nil, err
		}
	}
	return storage.AccountFromMap(out), nil
}

func (st *store) ListUserAccounts(ctx context.Context, userID string) ([]*storage.Account, error) {
	recs, err := st.base.FindMany(ctx, storage.ModelAccount,
		[]storage.Where{storage.W("userId", userID)}, nil)
	if err != nil {
		return nil, err
	}
	out := make([]*storage.Account, 0, len(recs))
	for _, rec := range recs {
		out = append(out, storage.AccountFromMap(rec))
	}
	return out, nil
}

func (st *store) FindAccount(ctx context.Context, providerID, accountID string) (*storage.Account, error) {
	rec, err := st.base.FindOne(ctx, storage.ModelAccount, []storage.Where{
		storage.W("providerId", providerID),
		storage.W("accountId", accountID),
	})
	if err != nil {
		return nil, err
	}
	return storage.AccountFromMap(rec), nil
}

func (st *store) FindCredentialAccount(ctx context.Context, userID string) (*storage.Account, error) {
	rec, err := st.base.FindOne(ctx, storage.ModelAccount, []storage.Where{
		storage.W("userId", userID),
		storage.W("providerId", "credential"),
	})
	if err != nil {
		return nil, err
	}
	return storage.AccountFromMap(rec), nil
}

func (st *store) UpdateAccount(ctx context.Context, id string, update map[string]any) (*storage.Account, error) {
	update["updatedAt"] = time.Now().UTC()
	rec, err := st.base.Update(ctx, storage.ModelAccount, []storage.Where{storage.W("id", id)}, update)
	if err != nil {
		return nil, err
	}
	return storage.AccountFromMap(rec), nil
}

func (st *store) DeleteAccount(ctx context.Context, id string) error {
	return st.base.Delete(ctx, storage.ModelAccount, []storage.Where{storage.W("id", id)})
}

// ---- verifications ----

func (st *store) CreateVerification(ctx context.Context, identifier, value string, expiresIn time.Duration) (*storage.Verification, error) {
	now := time.Now().UTC()
	v := &storage.Verification{
		ID:         st.generateID(storage.ModelVerification),
		Identifier: identifier,
		Value:      value,
		ExpiresAt:  now.Add(expiresIn),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if _, err := st.base.Create(ctx, storage.ModelVerification, storage.VerificationToMap(v)); err != nil {
		return nil, err
	}
	return v, nil
}

// FindVerification returns the latest live verification for identifier,
// deleting expired entries opportunistically.
func (st *store) FindVerification(ctx context.Context, identifier string) (*storage.Verification, error) {
	recs, err := st.base.FindMany(ctx, storage.ModelVerification,
		[]storage.Where{storage.W("identifier", identifier)},
		&storage.FindOptions{SortBy: &storage.SortBy{Field: "createdAt", Direction: "desc"}})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, rec := range recs {
		v := storage.VerificationFromMap(rec)
		if v.ExpiresAt.After(now) {
			return v, nil
		}
	}
	// clean up expired records
	_, _ = st.base.DeleteMany(ctx, storage.ModelVerification, []storage.Where{
		storage.W("identifier", identifier),
		{Field: "expiresAt", Operator: storage.OpLte, Value: now},
	})
	return nil, storage.ErrNotFound
}

func (st *store) DeleteVerification(ctx context.Context, id string) error {
	return st.base.Delete(ctx, storage.ModelVerification, []storage.Where{storage.W("id", id)})
}

func (st *store) DeleteVerificationsByIdentifier(ctx context.Context, identifier string) error {
	_, err := st.base.DeleteMany(ctx, storage.ModelVerification,
		[]storage.Where{storage.W("identifier", identifier)})
	return err
}
