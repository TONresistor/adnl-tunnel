package tunnel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

func init() {
	tl.Register(OverlayKey{}, "adnlTunnel.overlayKey paymentNode:int256 = adnlTunnel.OverlayKey")
	tl.Register(ClearnetOverlayKey{}, "adnlTunnel.clearnetOverlayKey paymentNode:int256 = adnlTunnel.ClearnetOverlayKey")
}

type OverlayKey struct {
	PaymentNode []byte `tl:"int256"`
}

type ClearnetOverlayKey struct {
	PaymentNode []byte `tl:"int256"`
}

// updateDHTOverlay stores or refreshes the gateway's node in the DHT overlay
// identified by keyObj. It handles find/refresh/replace/append logic.
func (g *Gateway) updateDHTOverlay(ctx context.Context, ttlSeconds int64, keyObj tl.Serializable) (int, error) {
	overlayKey, err := tl.Hash(keyObj)
	if err != nil {
		return 0, fmt.Errorf("failed to serialize key for dht overlay: %w", err)
	}

	nodesList, _, err := g.dht.FindOverlayNodes(ctx, overlayKey)
	if err != nil && !errors.Is(err, dht.ErrDHTValueIsNotFound) {
		return 0, fmt.Errorf("failed to find overlay nodes: %w", err)
	}

	if nodesList == nil {
		nodesList = &overlay.NodesList{}
	}

	node, err := overlay.NewNode(overlayKey, g.key)
	if err != nil {
		return 0, fmt.Errorf("failed creating overlay node: %w", err)
	}

	refreshed := false
	var newList []overlay.Node
	// refresh if already exists
	for i := range nodesList.List {
		id, ok := nodesList.List[i].ID.(keys.PublicKeyED25519)
		if ok && id.Key.Equal(node.ID.(keys.PublicKeyED25519).Key) {
			newList = append(newList, *node)
			refreshed = true
			break
		}

		// cleanup outdated ???
		if uint32(nodesList.List[i].Version) > uint32(time.Now().Unix()-ttlSeconds) {
			newList = append(newList, nodesList.List[i])
		}
	}
	nodesList.List = newList

	if !refreshed {
		// create if no records
		if len(nodesList.List) == 0 {
			nodesList = &overlay.NodesList{
				List: []overlay.Node{*node},
			}
		} else {
			if len(nodesList.List) >= 5 {
				sort.Slice(nodesList.List, func(i, j int) bool {
					return nodesList.List[i].Version < nodesList.List[j].Version
				})

				// replace oldest
				nodesList.List[0] = *node
			} else {
				// add our node if < 5 in list
				nodesList.List = append(nodesList.List, *node)
			}
		}
	}

	ovStored, _, err := g.dht.StoreOverlayNodes(ctx, overlayKey, nodesList, time.Duration(ttlSeconds)*time.Second, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to store overlay nodes: %w", err)
	}

	return ovStored, nil
}

// discoverNodesForKey finds public keys of nodes in the DHT overlay identified by keyObj.
func (g *Gateway) discoverNodesForKey(ctx context.Context, keyObj tl.Serializable) ([]ed25519.PublicKey, error) {
	overlayKey, err := tl.Hash(keyObj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key for dht overlay: %w", err)
	}

	nodesList, _, err := g.dht.FindOverlayNodes(ctx, overlayKey)
	if err != nil && !errors.Is(err, dht.ErrDHTValueIsNotFound) {
		return nil, fmt.Errorf("failed to find overlay nodes: %w", err)
	}

	if nodesList == nil {
		return nil, nil
	}

	var keysList []ed25519.PublicKey
	for _, node := range nodesList.List {
		id, ok := node.ID.(keys.PublicKeyED25519)
		if ok {
			keysList = append(keysList, id.Key)
		}
	}

	return keysList, nil
}

func (g *Gateway) updateDHT(ctx context.Context, ttlSeconds int64) error {
	addr := g.gate.GetAddressList()
	stored, _, err := g.dht.StoreAddress(ctx, addr, time.Duration(ttlSeconds)*time.Second, g.key, 0)
	if err != nil && stored == 0 {
		return fmt.Errorf("failed to store address: %w", err)
	}

	pn := g.paymentNode
	if len(pn) == 0 {
		pn = make([]byte, 32)
	}

	ovStored, err := g.updateDHTOverlay(ctx, ttlSeconds, OverlayKey{PaymentNode: pn})
	if err != nil {
		return err
	}

	g.log.Debug().Int("addr_nodes", stored).Int("overlay_nodes", ovStored).Msg("dht records updated")
	return nil
}

func (g *Gateway) updateClearnetDHT(ctx context.Context, ttlSeconds int64) error {
	// StoreAddress is already done by updateDHT in the same cycle
	pn := g.paymentNode
	if len(pn) == 0 {
		pn = make([]byte, 32)
	}

	ovStored, err := g.updateDHTOverlay(ctx, ttlSeconds, ClearnetOverlayKey{PaymentNode: pn})
	if err != nil {
		return err
	}

	g.log.Debug().Int("overlay_nodes", ovStored).Msg("clearnet dht records updated")
	return nil
}

func (g *Gateway) DiscoverClearnetNodes(ctx context.Context) ([]ed25519.PublicKey, error) {
	pn := g.paymentNode
	if len(pn) == 0 {
		pn = make([]byte, 32)
	}
	return g.discoverNodesForKey(ctx, ClearnetOverlayKey{PaymentNode: pn})
}

func (g *Gateway) DiscoverNodes(ctx context.Context) ([]ed25519.PublicKey, error) {
	pn := g.paymentNode
	if len(pn) == 0 {
		pn = make([]byte, 32)
	}
	return g.discoverNodesForKey(ctx, OverlayKey{PaymentNode: pn})
}
