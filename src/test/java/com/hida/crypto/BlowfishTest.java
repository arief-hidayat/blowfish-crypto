package com.hida.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.*;

@Test
public class BlowfishTest {


    @DataProvider(name = "licenses")
    public static Object[][] licenses() {
        return new Object[][] {
                {"IMMS_VALETTA:20140101:20170101", "arief.is.awesome" , "Sn/9lVcPG/89Lqh7GMGptrbKHtc4CbJ/91//rBjz/Ko=" },
                {"IMMS_JAKARTA:20140101:20170101", "arief.is.awesome" , "nvl9aVLek50UPFCAHxlNVrbKHtc4CbJ/91//rBjz/Ko=" },
                {"IMMS:20140101:20200101", "arief.is.awesome" , "ok3rZJBiC7q2yh7XOAmyfwav/sJwxY5v" }
        };
    }
    @Test(dataProvider = "licenses")
    void should_be_encrypted(String message, String password, String expectedHashKey) throws InvalidCipherTextException {
        assertThat(Blowfish.encryptBase64(message, password)).isEqualTo(expectedHashKey);
    }


    @Test(dataProvider = "licenses")
    void should_be_dencrypted(String message, String password, String expectedHashKey)  {
        assertThat(Blowfish.decryptBase64(expectedHashKey, password)).isEqualTo(message);
    }
}
