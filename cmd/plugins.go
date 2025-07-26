package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/bugbounty-tool/internal/plugins"
)

var pluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "Manage plugins and extensions",
	Long: `Manage plugins and extensions for the bug bounty tool:

- List available plugins
- Install new plugins from repository
- Update existing plugins
- Remove plugins
- Enable/disable plugins
- Configure plugin settings`,
}

var listPluginsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available plugins",
	RunE:  runListPlugins,
}

var installPluginCmd = &cobra.Command{
	Use:   "install [plugin-name]",
	Short: "Install a plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runInstallPlugin,
}

var removePluginCmd = &cobra.Command{
	Use:   "remove [plugin-name]",
	Short: "Remove a plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemovePlugin,
}

var updatePluginsCmd = &cobra.Command{
	Use:   "update",
	Short: "Update all plugins",
	RunE:  runUpdatePlugins,
}

func init() {
	rootCmd.AddCommand(pluginsCmd)
	
	pluginsCmd.AddCommand(listPluginsCmd)
	pluginsCmd.AddCommand(installPluginCmd)
	pluginsCmd.AddCommand(removePluginCmd)
	pluginsCmd.AddCommand(updatePluginsCmd)

	// Plugin flags
	installPluginCmd.Flags().String("source", "official", "plugin source (official, community, file)")
	installPluginCmd.Flags().String("version", "latest", "plugin version to install")
	installPluginCmd.Flags().Bool("force", false, "force installation")
}

func runListPlugins(cmd *cobra.Command, args []string) error {
	manager, err := plugins.NewManager(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}

	pluginList, err := manager.List()
	if err != nil {
		return fmt.Errorf("failed to list plugins: %w", err)
	}

	fmt.Printf("\n🔌 Available Plugins\n")
	fmt.Printf("═══════════════════════════════════\n")

	for _, plugin := range pluginList {
		status := "❌ Disabled"
		if plugin.Enabled {
			status = "✅ Enabled"
		}
		
		fmt.Printf("📦 %s v%s - %s\n", plugin.Name, plugin.Version, status)
		fmt.Printf("   %s\n", plugin.Description)
		fmt.Printf("   📁 %s\n\n", plugin.Path)
	}

	return nil
}

func runInstallPlugin(cmd *cobra.Command, args []string) error {
	pluginName := args[0]
	
	manager, err := plugins.NewManager(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}

	log.Info("Installing plugin", "name", pluginName)

	err = manager.Install(pluginName, &plugins.InstallOptions{
		Source:  cmd.Flag("source").Value.String(),
		Version: cmd.Flag("version").Value.String(),
		Force:   cmd.Flag("force").Value.String() == "true",
	})
	
	if err != nil {
		return fmt.Errorf("failed to install plugin: %w", err)
	}

	fmt.Printf("✅ Plugin '%s' installed successfully\n", pluginName)
	return nil
}

func runRemovePlugin(cmd *cobra.Command, args []string) error {
	pluginName := args[0]
	
	manager, err := plugins.NewManager(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}

	log.Info("Removing plugin", "name", pluginName)

	err = manager.Remove(pluginName)
	if err != nil {
		return fmt.Errorf("failed to remove plugin: %w", err)
	}

	fmt.Printf("✅ Plugin '%s' removed successfully\n", pluginName)
	return nil
}

func runUpdatePlugins(cmd *cobra.Command, args []string) error {
	manager, err := plugins.NewManager(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}

	log.Info("Updating all plugins")

	results, err := manager.UpdateAll()
	if err != nil {
		return fmt.Errorf("failed to update plugins: %w", err)
	}

	fmt.Printf("\n🔄 Plugin Update Results\n")
	fmt.Printf("═══════════════════════════════════\n")
	
	for pluginName, result := range results {
		if result.Updated {
			fmt.Printf("✅ %s: %s → %s\n", pluginName, result.OldVersion, result.NewVersion)
		} else {
			fmt.Printf("➖ %s: %s (up to date)\n", pluginName, result.OldVersion)
		}
	}

	return nil
}
