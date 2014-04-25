package com.hida.crypto;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class Blowfish {
    public static byte[] process(byte[] data, String password) throws InvalidCipherTextException {
        return process(data, password, true);
    }
    /**
     * Encrypts or decrypts a byte array.
     *
     * @param data Data to be encrypted or decrypted
     * @param password Password to use
     * @param encrypting Are we encrypting or decrypting?
     *
     */
    public static byte[] process(byte[] data, String password, boolean encrypting) throws InvalidCipherTextException {
        BlowfishEngine engine = new BlowfishEngine();
        KeyParameter key = new KeyParameter(password.getBytes());

        engine.init(encrypting, key);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
        cipher.init(encrypting, key);

        byte[] outBytes = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, outBytes, 0);
        cipher.doFinal(outBytes, len);
        return outBytes;
    }

    /**
     * Encrypts a byte array and returns the result
     */
    public static byte[] encrypt(byte[] data, String password) throws InvalidCipherTextException {
        return Blowfish.process(data, password, true);
    }

    /**
     * Decrypts a byte array and returns the result. In case of an error,
     * it returns null
     */
    public static byte[] decrypt(byte[] data, String password) {
        byte[] result = null;
        try {
            result = Blowfish.process(data, password, false);
        }
        catch (Exception e) {
            // An exception will be raised if decryption fails.  We return
            // null in that case
        }
        return result;

    }

    /**
     * Encrypts a byte array and returns a base64-encoded string
     *
     */
    public static String encryptBase64(byte[] data, String password) throws InvalidCipherTextException {
        byte[] result = encrypt(data, password);
        return new String(Base64.encodeBase64(result));
    }

    /**
     * Encrypts a string and returns the result base64-encoded
     */
    public static String encryptBase64(String data, String password) throws InvalidCipherTextException {
        return encryptBase64(data.getBytes(), password);
    }

    /**
     * Decrypts a base64-encoded string and returns the result. In case of an
     * error, it returns null
     */
    public static String decryptBase64(String data, String password) {
        return decryptBase64(data, password, true);
    }

    public static String decryptBase64(String data, String password, boolean trim) {
        byte[] result = decrypt(Base64.decodeBase64(data), password);
        String str = null;
        if (result != null && result.length > 0) {
            str = new String(result);
            if (trim) str = str.trim();
        }
        return str;
    }
}
