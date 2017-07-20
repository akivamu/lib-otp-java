import com.akivamu.otp.java.TOTP;
import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class OtpTest {
    @Test
    public void testSimple() throws NoSuchAlgorithmException, InvalidKeyException {
        long time = 1500525852009L;

        Assert.assertEquals("557487", TOTP.generateToken("TQCEOJ5TVODDC2MT", time));
        Assert.assertEquals("695218", TOTP.generateToken("ufsv mhe5 ztrt fcpa hr7r fe3p wn4q bstc", time));

        time = 1500551085162L;
        Assert.assertEquals("067530", TOTP.generateToken("atbr esm5 igmg vjv2 ac7s deqi 5bq4 fyhs", time));

        runNow();
    }

    private void runNow() {
        long now = System.currentTimeMillis();
        System.out.println(now + " - " + TOTP.generateToken("atbr esm5 igmg vjv2 ac7s deqi 5bq4 fyhs", now));
    }
}
