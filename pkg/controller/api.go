package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"vxlan-controller/pkg/apisock"
	"vxlan-controller/pkg/config"
	"vxlan-controller/pkg/types"
	"vxlan-controller/pkg/vlog"
)

func (c *Controller) apiServer() {
	sockPath := c.Config.APISocket
	if sockPath == "" {
		sockPath = config.DefaultControllerSocket
	}

	if err := apisock.ListenAndServe(c.ctx, sockPath, c.handleAPI); err != nil {
		vlog.Errorf("[Controller] API server error: %v", err)
	}
}

func (c *Controller) handleAPI(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case "cost.get":
		return c.apiCostGet()
	case "cost.getmode":
		return c.apiCostGetMode()
	case "cost.setmode":
		return c.apiCostSetMode(params)
	case "cost.store":
		return c.apiCostStore()
	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

// AFCostInfo is the per-AF cost data returned by cost.get.
type AFCostInfo struct {
	Mean           float64 `json:"mean"`
	Std            float64 `json:"std"`
	PacketLoss     float64 `json:"packet_loss"`
	Priority       int     `json:"priority"`
	AdditionalCost float64 `json:"additional_cost"`
	TotalCost      float64 `json:"total_cost"`
}

// CostGetResult is the result of cost.get.
type CostGetResult struct {
	CostMode string                                  `json:"cost_mode"`
	Matrix   map[string]map[string]map[string]*AFCostInfo `json:"matrix"` // [src_name][dst_name][af]
}

func (c *Controller) apiCostGet() (*CostGetResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := &CostGetResult{
		CostMode: c.CostMode,
		Matrix:   make(map[string]map[string]map[string]*AFCostInfo),
	}

	for srcID, dsts := range c.State.LatencyMatrix {
		srcName := c.clientNameByID(srcID)
		if result.Matrix[srcName] == nil {
			result.Matrix[srcName] = make(map[string]map[string]*AFCostInfo)
		}
		for dstID, li := range dsts {
			dstName := c.clientNameByID(dstID)
			if result.Matrix[srcName][dstName] == nil {
				result.Matrix[srcName][dstName] = make(map[string]*AFCostInfo)
			}
			for af, al := range li.AFs {
				result.Matrix[srcName][dstName][string(af)] = &AFCostInfo{
					Mean:           al.Mean,
					Std:            al.Std,
					PacketLoss:     al.PacketLoss,
					Priority:       al.Priority,
					AdditionalCost: al.AdditionalCost,
					TotalCost:      al.Mean + al.AdditionalCost,
				}
			}
		}
	}

	return result, nil
}

func (c *Controller) apiCostGetMode() (map[string]string, error) {
	c.mu.Lock()
	mode := c.CostMode
	c.mu.Unlock()
	return map[string]string{"mode": mode}, nil
}

type costSetModeParams struct {
	Mode string `json:"mode"`
}

func (c *Controller) apiCostSetMode(params json.RawMessage) (interface{}, error) {
	var p costSetModeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Mode != "probe" && p.Mode != "static" {
		return nil, fmt.Errorf("invalid mode %q (must be probe or static)", p.Mode)
	}

	if p.Mode == "static" {
		c.mu.Lock()
		hasStatic := c.staticCostsByID != nil && len(c.staticCostsByID) > 0
		c.mu.Unlock()
		if !hasStatic {
			return nil, fmt.Errorf("no static costs configured; use 'cost store' first")
		}
	}

	c.mu.Lock()
	c.CostMode = p.Mode
	c.mu.Unlock()

	// Trigger topology recomputation with new mode
	c.triggerTopologyUpdate()

	return map[string]string{"mode": p.Mode}, nil
}

func (c *Controller) apiCostStore() (interface{}, error) {
	// Read current latency matrix under lock
	c.mu.Lock()
	nameCosts := make(map[string]map[string]map[string]float64)
	for srcID, dsts := range c.State.LatencyMatrix {
		srcName := c.clientNameByID(srcID)
		if nameCosts[srcName] == nil {
			nameCosts[srcName] = make(map[string]map[string]float64)
		}
		for dstID, li := range dsts {
			dstName := c.clientNameByID(dstID)
			if nameCosts[srcName][dstName] == nil {
				nameCosts[srcName][dstName] = make(map[string]float64)
			}
			for af, al := range li.AFs {
				if al.PacketLoss >= 1.0 {
					continue // skip unreachable
				}
				nameCosts[srcName][dstName][string(af)] = al.Mean + al.AdditionalCost
			}
		}
	}
	configPath := c.Config.ConfigPath
	c.mu.Unlock()

	// Write to config file
	if configPath == "" {
		return nil, fmt.Errorf("config path not available")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var raw config.ControllerConfigFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	raw.StaticCosts = nameCosts
	// Don't change cost_mode here - admin decides when to switch

	newData, err := yaml.Marshal(&raw)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	// Atomic write: temp file + rename
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, newData, 0644); err != nil {
		return nil, fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("rename config: %w", err)
	}

	// Update in-memory static costs
	c.mu.Lock()
	// Convert name costs to AFName-keyed for in-memory storage
	afNameCosts := make(map[string]map[string]map[types.AFName]float64)
	for src, dsts := range nameCosts {
		afNameCosts[src] = make(map[string]map[types.AFName]float64)
		for dst, afs := range dsts {
			afNameCosts[src][dst] = make(map[types.AFName]float64)
			for af, cost := range afs {
				afNameCosts[src][dst][types.AFName(af)] = cost
			}
		}
	}
	c.Config.StaticCosts = afNameCosts
	c.staticCostsByID = c.resolveStaticCosts(afNameCosts)
	c.mu.Unlock()

	// Count entries for display
	count := 0
	for _, dsts := range nameCosts {
		for _, afs := range dsts {
			count += len(afs)
		}
	}

	vlog.Infof("[Controller] cost store: saved %d cost entries to %s", count, filepath.Base(configPath))
	return map[string]int{"entries": count}, nil
}
