package crypto

import (
	"crypto"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewJWKSFromRSAKey(t *testing.T) {
	key, err := Generate4096BitsRSAKey()
	require.Nil(t, err)

	keys := []crypto.PublicKey{
		key.Public,
	}

	keySet, err := NewKeySet(keys)
	require.Nil(t, err)
	key1 := keySet.Keys[0]
	keyID := key1.KeyID

	// assert the json web key AND the json web key set can both be properly marshaled
	b, err := key1.MarshalJSON()
	require.Nil(t, err)

	b, err = json.Marshal(keySet)
	require.Nil(t, err)
	fmt.Println(string(b))

	// assert that the key we can look up a JWKS by key ID
	gotKey := keySet.Key(keyID)[0]
	require.True(t, reflect.DeepEqual(key1, gotKey))

	// assert that the key ID is computed correctly
	gotKeyID, err := GetKeyID(key.Public)
	require.Nil(t, err)
	require.Equal(t, keyID, gotKeyID)

	// assert that the keys are valid
	for _, key := range keySet.Keys {
		require.True(t, key.Valid())
	}
}
