package gamecubeloader.common;

import java.io.File;
import java.util.ArrayList;

import javax.swing.filechooser.FileSystemView;

public final class DolphinEmulatorUtil {

    private DolphinEmulatorUtil() {
        // This should not be instantiated.
    }

    /**
     * Try to find the path of a global Dolphin Emulator User folder.
     * 
     * @return The directory to Dolphin Emulator User folder, or {@code null} if not
     *         found.
     * @see #getGlobalUserFolder(String)
     */
    public static File getGlobalUserFolder() {
        return getGlobalUserFolder(null);
    }

    /**
     * Try to find the path of a global Dolphin Emulator User folder and make sure
     * {@code sub} exists.
     * 
     * @param sub A sub-folder or file inside the Dolphin Emulator User folder to
     *            make sure it exists. If {@code null}, it only checks for the User
     *            folder.
     * @return The directory or file inside Dolphin Emulator User folder if
     *         {@code sub} is non-{@code null}, or the directory to the Dolphin
     *         Emulator User folder, or {@code null} if not found in any case.
     * @see #getGlobalUserFolder()
     */
    public static File getGlobalUserFolder(String sub) {
        // https://github.com/dolphin-emu/dolphin/blob/dbc7e035773d97293f572b9fe15fdcb877fc3965/Source/Core/UICommon/UICommon.cpp#L285

        var possible_paths = new ArrayList<String>(5);

        if (System.getProperty("os.name", "Unknown").toUpperCase().startsWith("WINDOWS")) {
            // TODO: Registry HKCU\Software\Dolphin Emulator\UserConfigPath

            String documentsPath = FileSystemView.getFileSystemView().getDefaultDirectory().getPath();
            possible_paths.add(documentsPath + "\\Dolphin Emulator\\");

            try {
                String envAppdata = System.getenv("APPDATA");
                if (envAppdata != null && !envAppdata.isBlank()) {
                    possible_paths.add(envAppdata + "\\Roaming\\Dolphin Emulator\\");
                }
            } catch (SecurityException e) {
                // Do nothing, pretend it didn't exists.
            }
        } else {
            try {
                String envUserPath = System.getenv("DOLPHIN_EMU_USERPATH");
                if (envUserPath != null && !envUserPath.isBlank()) {
                    possible_paths.add(envUserPath);
                }
            } catch (SecurityException e) {
                // Do nothing, pretend it didn't exists.
            }
            
            var userHome = System.getProperty("user.home");
            possible_paths.add(userHome + File.separator + ".dolphin-emu" + File.separator);

            var xdg_data_home = System.getenv("XDG_DATA_HOME");
            if (xdg_data_home == null || xdg_data_home.isBlank()) {
                xdg_data_home = userHome + File.separator + ".local" + File.separator + "share";
            }
            possible_paths.add(xdg_data_home + File.separator + "dolphin-emu" + File.separator);
        }

        for (var path : possible_paths) {
            var dir = sub == null ? new File(path) : new File(path, sub);
            if (dir.exists()) {
                return dir;
            }
        }

        return null;
    }

}
