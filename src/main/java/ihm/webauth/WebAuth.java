package ihm.webauth;

import org.bukkit.plugin.java.JavaPlugin;

public class WebAuth extends JavaPlugin {
    public static WebAuth INSTANCE;

    @Override
    public void onEnable() {
        INSTANCE = this;

        getCommand("changepass").setExecutor(new Commands.ChangePass());
        getCommand("logout").setExecutor(new Commands.Logout());
        getCommand("pass").setExecutor(new Commands.Pass());
        getCommand("webauth").setExecutor(new Commands.AdminCommand());

        getServer().getPluginManager().registerEvents(new WebAuthListener(), this);

        // Copies config.yml in resources to data folder
        saveDefaultConfig();

        Database.init();

        getLogger().info("Starting HTTPS server on port " + getConfig().getInt("port"));
        WebServer.init();
    }

    @Override
    public void onDisable() {
    }
}
