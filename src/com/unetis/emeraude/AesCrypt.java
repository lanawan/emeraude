package com.unetis.emeraude;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AesCrypt {
	byte [] mac;

    public AesCrypt(String keyOption) throws SocketException, UnknownHostException {
    	InetAddress ip = InetAddress.getLocalHost();
    	NetworkInterface network = NetworkInterface.getByInetAddress(ip);
		mac = (keyOption + toHex(network.getHardwareAddress())).getBytes();
    }

    public String encrypt(String cleartext) throws AesException {
    	try {
        	byte[] rawKey = getRawKey(mac);
            byte[] result = new byte[0];
            result = encrypt(rawKey, cleartext.getBytes());
            return toHex(result);
        } catch (NoSuchAlgorithmException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (NoSuchPaddingException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (InvalidKeyException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (IllegalBlockSizeException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (BadPaddingException e) {
        	throw new AesException("AES encrypt error", e);
        }
    }
    public String encrypt(byte[] bindata) throws AesException {
    	try {
        	byte[] rawKey = getRawKey(mac);
            byte[] result = new byte[0];
            result = encrypt(rawKey, bindata);
            return toHex(result);
        } catch (NoSuchAlgorithmException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (NoSuchPaddingException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (InvalidKeyException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (IllegalBlockSizeException e) {
        	throw new AesException("AES encrypt error", e);
        } catch (BadPaddingException e) {
        	throw new AesException("AES encrypt error", e);
        }
    }
    public byte[] decrypt(String encrypted) throws AesException {
    	byte[] rawKey = new byte[0];
        try {
        	rawKey = getRawKey(mac);
            byte[] enc = toByte(encrypted);
            byte[] result = new byte[0];
            result = decrypt(rawKey, enc);
            return result;
        } catch (NoSuchAlgorithmException e) {
        	throw new AesException("AES decrypt error", e);
        } catch (NoSuchPaddingException e) {
        	throw new AesException("AES decrypt error", e);
        } catch (InvalidKeyException e) {
        	throw new AesException("AES decrypt error", e);
        } catch (IllegalBlockSizeException e) {
        	throw new AesException("AES decrypt error", e);
        } catch (BadPaddingException e) {
        	throw new AesException("AES decrypt error", e);
        }
    }
    private byte[] getRawKey(byte[] password) throws NoSuchAlgorithmException {
    	KeyGenerator kgen = KeyGenerator.getInstance("AES");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(password);
        kgen.init(256, sr); // 192 and 256 bits may not be available
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        return raw;
    }

    private byte[] encrypt(byte[] raw, byte[] clear)
    		throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    	SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }

    private byte[] decrypt(byte[] raw, byte[] encrypted)
    		throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    	SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

    private String toHex(byte [] buffer) {
    	return DatatypeConverter.printBase64Binary(buffer);
    }

    private byte[] toByte(String hex) {
    	return DatatypeConverter.parseBase64Binary(hex);
    }
}