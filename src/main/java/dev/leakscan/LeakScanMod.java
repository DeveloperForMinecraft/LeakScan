package dev.leakscan;

import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.loading.FMLEnvironment;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Mod(LeakScanMod.ID)
public class LeakScanMod {
    public static final String ID = "leakscan";
    public static final Logger LOGGER = LogManager.getLogger("LeakScan");

    public LeakScanMod() {
        // Client-side mod: load nothing on a dedicated server.
        if (FMLEnvironment.dist == Dist.CLIENT) {
            ClientHooks.init();
        }
    }
}
