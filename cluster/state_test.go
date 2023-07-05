package cluster

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes/fake"
)

// Tests the scenario where the cluster stores no existing state. In this case, a new full state secret should be
// created.
func Test_SaveAndGetFullStateFromK8s_ClusterWithoutSecret(t *testing.T) {
	ctx := context.Background()
	rkeConf := GetLocalRKEConfig()
	fullState := FullState{
		CurrentState: State{
			RancherKubernetesEngineConfig: rkeConf,
		},
	}
	client := fake.NewSimpleClientset()

	// Saving should create a new secret.
	err := SaveFullStateToK8s(ctx, client, &fullState)
	assert.NoError(t, err)

	fetchedFullState, err := GetFullStateFromK8s(ctx, client)
	assert.NoError(t, err)
	assert.Equal(t, *fetchedFullState, fullState)
}

// Tests the scenario where the cluster already stores a full state secret. In this case, the full state secret should
// be updated.
func Test_SaveAndGetFullStateFromK8s_ClusterWithSecret(t *testing.T) {
	ctx := context.Background()
	rkeConf := GetLocalRKEConfig()
	fullState := FullState{
		CurrentState: State{
			RancherKubernetesEngineConfig: rkeConf,
		},
	}
	client := fake.NewSimpleClientset()

	// Saving should create a new secret.
	err := SaveFullStateToK8s(ctx, client, &fullState)
	assert.NoError(t, err)

	// Saving again should update the existing secret.
	fullState.CurrentState.EncryptionConfig = "asdf"
	err = SaveFullStateToK8s(ctx, client, &fullState)
	assert.NoError(t, err)

	fetchedFullState, err := GetFullStateFromK8s(ctx, client)
	assert.NoError(t, err)
	assert.Equal(t, *fetchedFullState, fullState)
}

// Tests the scenario where the cluster already stores existing state in a configmap. In this case, a new full state
// secret should be created and the configmap should be deleted.
func Test_SaveAndGetFullStateFromK8s_OldClusterWithConfigMap(t *testing.T) {
	ctx := context.Background()
	rkeConf := GetLocalRKEConfig()
	client := fake.NewSimpleClientset()
	fullState := FullState{
		CurrentState: State{
			RancherKubernetesEngineConfig: rkeConf,
		},
	}
	fullStateBytes, err := json.Marshal(fullState)
	assert.NoError(t, err)
	configMap := v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: FullStateConfigMapName,
		},
		Data: map[string]string{
			FullStateConfigMapName: string(fullStateBytes),
		},
	}

	// Create the old full cluster state configmap
	_, err = client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Create(ctx, &configMap, metav1.CreateOptions{})
	assert.NoError(t, err)

	// Make sure we can still fall back to it given that the secret does not yet exist.
	fetchedFullState, err := GetFullStateFromK8s(ctx, client)
	assert.NoError(t, err)
	assert.Equal(t, *fetchedFullState, fullState)

	// Saving should create a new secret.
	err = SaveFullStateToK8s(ctx, client, &fullState)
	assert.NoError(t, err)

	// The old configmap should have been removed.
	_, err = client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx, FullStateConfigMapName, metav1.GetOptions{})
	assert.True(t, apierrors.IsNotFound(err))

	// We should now get the state from the secret.
	fetchedFullState, err = GetFullStateFromK8s(ctx, client)
	assert.NoError(t, err)
	assert.Equal(t, *fetchedFullState, fullState)
}
