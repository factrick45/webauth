package ihm.webauth;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public class Commands {
    public static class AdminCommand implements CommandExecutor {
        @Override
        public boolean onCommand(
            CommandSender sender,
            Command command,
            String label,
            String[] args
        ) {
            if (args.length < 1)
                return false;

            switch(args[0]) {
            case "add":
                if (args.length != 2) {
                    sender.sendMessage("/webauth add <username>");
                    return true;
                }
                if (!Database.userAdd(args[1])) {
                    sender.sendMessage("User already exists!");
                    return true;
                }
                sender.sendMessage("Successfully added " + args[1] + ".");
                break;
            case "del":
                if (args.length != 2) {
                    sender.sendMessage("/webauth del <username>");
                    return true;
                }
                if (!Database.userDel(args[1])) {
                    sender.sendMessage("User doesn't exist!");
                    return true;
                }
                sender.sendMessage("Successfully removed " + args[1] + ".");
                break;
            default:
                return false;
            }

            return true;
        }
    }

    private static class PlayerCommand implements CommandExecutor {
        private String usage;
        private Player player;

        @Override
        public boolean onCommand(
            CommandSender sender,
            Command command,
            String label,
            String[] args
        ) {
            if (!(sender instanceof Player))
                return true;

            player = (Player) sender;
            usage = command.getUsage();
            return onCommand(player, args);
        }

        public boolean onCommand(Player player, String[] args) {
            return true;
        }

        protected void sendUsage() {
            player.sendMessage(usage);
        }
    }

    public static class ChangePass extends PlayerCommand {
        @Override
        public boolean onCommand(Player player, String[] args) {
            if (args.length != 3)
                return false;
            if (Database.getPass(player.getName()) == null) {
                player.sendMessage("You have no password set! Use /pass instead.");
                return true;
            }
            if (!args[1].equals(args[2])) {
                player.sendMessage("Passwords do not match.");
                return false;
            }

            // This probably causes a race condition but at least the server
            // doesn't freeze
            new Thread(() -> {
                if (!Database.verifyPass(player.getName(), args[0])) {
                    player.sendMessage("Incorrect password.");
                    sendUsage();
                    return;
                }

                Database.setPass(player.getName(), args[1]);
                player.sendMessage("Password set successfully.");
            }).start();
            return true;
        }
    }

    public static class Logout extends PlayerCommand {
        @Override
        public boolean onCommand(Player player, String[] args) {
            Database.logout(player.getName());
            player.kickPlayer("Logged out.");
            return true;
        }
    }

    public static class Pass extends PlayerCommand {
        @Override
        public boolean onCommand(Player player, String[] args) {
            if (args.length != 2)
                return false;
            if (Database.getPass(player.getName()) != null) {
                player.sendMessage("Your password is already set! Use /changepass instead.");
                return true;
            }
            if (!args[0].equals(args[1])) {
                player.sendMessage("Passwords do not match.");
                return false;
            }

            new Thread(() -> {
                Database.setPass(player.getName(), args[0]);
                player.sendMessage("Password set successfully.");
            }).start();
            return true;
        }
    }
}
