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
}
