package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

func newMeshCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "mesh",
		Short: "Show the mesh topology (nodes, repeaters, links)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			topo, err := c.MeshTopology(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "mesh failed")
			}
			if asJSON {
				return printJSON(topo)
			}
			for _, n := range topo.Nodes {
				role := n.MeshRole
				if role == "" {
					role = "client"
				}
				fmt.Printf("● %s  [%s%s]\n", orDash(n.DeviceName), role, modelSuffix(n.DeviceModel))
				for _, iface := range n.Interfaces {
					for _, link := range iface.Links {
						if link.State == "" {
							continue
						}
						peer := topo.NodeName(link.Node2)
						if peer == n.DeviceName || peer == link.Node2 {
							peer = topo.NodeName(link.Node1)
						}
						fmt.Printf("    %-5s %-9s → %-20s %s\n",
							iface.Type, link.State, peer, dataRate(link))
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}
