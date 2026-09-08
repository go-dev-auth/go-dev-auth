package godevauth

import (
	"context"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// deleteUserPluginData removes rows in plugin tables that reference the
// user, using db as the executor (a transaction, when DeleteUser runs
// inside one).
//
// On PostgreSQL and (since the MySQL foreign-key fix) MySQL, the ON
// DELETE CASCADE constraint the schema declares already removes these
// rows when the user row goes, and this pass simply finds nothing extra
// to do. It exists for the adapters that do not enforce foreign keys —
// the in-memory and MongoDB adapters, and SQLite when it is opened
// without the foreign_keys pragma — where without it a deleted user's
// 2FA secrets, API keys, passkeys and organization memberships would be
// orphaned and, worse, adopted by the next user to reuse the id.
func (a *Auth) deleteUserPluginData(ctx context.Context, db storage.Adapter, userID string) error {
	if a.schema == nil {
		return nil
	}
	for name, table := range a.schema.Tables {
		if name == storage.ModelUser || name == storage.ModelSession || name == storage.ModelAccount {
			continue // handled explicitly by DeleteUser
		}
		field := userReferenceField(table)
		if field == "" {
			continue
		}
		if _, err := db.DeleteMany(ctx, name, []storage.Where{storage.W(field, userID)}); err != nil {
			return err
		}
	}
	return nil
}

// userReferenceField returns the name of the column in table that
// references the user table, or "" if none does.
func userReferenceField(table *storage.Table) string {
	for _, f := range table.Fields {
		if f.References != nil && f.References.Model == storage.ModelUser {
			return f.Name
		}
	}
	return ""
}
