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
    }
}
