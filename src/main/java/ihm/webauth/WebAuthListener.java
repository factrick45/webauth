package ihm.webauth;

import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;

public class WebAuthListener implements Listener {
    @EventHandler
    public void onPlayerLogin(PlayerLoginEvent event) {
        // Prevent exceptions from allowing the player to log in
        try {
            if (Database.isLoggedIn(event.getPlayer().getName(), event.getAddress()))
              return;
        } catch (Exception e) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, "Internal error");
            throw e;
        }
        String url = WebAuth.INSTANCE.getConfig().getString("refer-url");
        event.disallow(
            PlayerLoginEvent.Result.KICK_OTHER,
            "Please authenticate at \u00A74" + url
        );
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (Database.getPass(event.getPlayer().getName()) == null) {
            event.getPlayer().sendMessage("\u00A76Your password is NOT set. Set it with /pass.");
            event.getPlayer().sendTitle("\u00A76Your password is NOT set.", "Set it with /pass.");
        }
    }
}
