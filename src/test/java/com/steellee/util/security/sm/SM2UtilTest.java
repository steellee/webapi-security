package com.steellee.util.security.sm;

import com.steellee.util.security.sm.util.FileUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;

public class SM2UtilTest {
    // 源数据
    public static final byte[] SRC_DATA = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    // 用户ID标识， 可为null
    public static final byte[] WITH_ID = new byte[]{1, 2, 3, 4};

    public static void main(String[] args) {
    }

    /**
     * 生成随机秘钥对
     */
    @Test
    public void testGenerateKeyPair() {

        AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
        ECPrivateKeyParameters priKey = (ECPrivateKeyParameters)keyPair.getPrivate();
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)keyPair.getPublic();
        System.out.println("Pri Hex:" + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
        System.out.println("Pub X Hex:" + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
        System.out.println("Pub X Hex:" + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
        System.out.println("Pub Point Hex:" + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

         /*Pri Hex:315BACF546B53F044AEC2C2F6794A74CF5442A0455ABDDA861F3B9C52DAA0A76
            Pub X Hex:F1A3C8FA5CC4183DD113FDB1817EC92C5B5A5C4259A360EACB177A4C85C24BBE
            Pub X Hex:5FD20DEC765D5CE9C9E477354FB4F5C548C67676F8D684986B7238D2880823BC
            Pub Point Hex:04F1A3C8FA5CC4183DD113FDB1817EC92C5B5A5C4259A360EACB177A4C85C24BBE5FD20DEC765D5CE9C9E477354FB4F5C548C67676F8D684986B7238D2880823BC*/
    }
    /**
     * 验签测试1
     */
    @Test
    public void testSignAndVerify1() {
        try {
            // 1，提供客户端的公钥字符串
            /*Pri Hex:315BACF546B53F044AEC2C2F6794A74CF5442A0455ABDDA861F3B9C52DAA0A76
            Pub X Hex:F1A3C8FA5CC4183DD113FDB1817EC92C5B5A5C4259A360EACB177A4C85C24BBE
            Pub X Hex:5FD20DEC765D5CE9C9E477354FB4F5C548C67676F8D684986B7238D2880823BC
            Pub Point Hex:04F1A3C8FA5CC4183DD113FDB1817EC92C5B5A5C4259A360EACB177A4C85C24BBE5FD20DEC765D5CE9C9E477354FB4F5C548C67676F8D684986B7238D2880823BC*/
            // 私钥
            String priHex = "315BACF546B53F044AEC2C2F6794A74CF5442A0455ABDDA861F3B9C52DAA0A76";
            // 公钥X
            String pubxHex = "F1A3C8FA5CC4183DD113FDB1817EC92C5B5A5C4259A360EACB177A4C85C24BBE";
            // 公钥Y
            String pubyHex = "5FD20DEC765D5CE9C9E477354FB4F5C548C67676F8D684986B7238D2880823BC";

            // --------------------------------客户端--------------------------------
            // 得到client私钥对象
            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                new BigInteger(ByteUtils.fromHexString(priHex)), SM2Util.DOMAIN_PARAMS);

            // 2，client的私钥签名
            byte[] sign = SM2Util.sign(priKey, SRC_DATA);
            System.out.println("SM2 sign result:\n" + ByteUtils.toHexString(sign));

            // --------------------------------服务端--------------------------------
            // 得到client公钥钥对象
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(pubxHex, pubyHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

            // 3，client的公钥验签
            boolean flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 验签测试2
     */
    @Test
    public void testSignAndVerify2() {
        try {
            // 1，提供客户端的公钥
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            /*System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());*/

            // --------------------------------客户端--------------------------------
            // 2，client的私钥签名
            byte[] sign = SM2Util.sign(priKey, WITH_ID, SRC_DATA);
            System.out.println("1) SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            // 将DER编码的SM2签名解析成64字节的纯R+S字节流
            byte[] rawSign = SM2Util.decodeDERSM2Sign(sign);
            sign = SM2Util.encodeSM2SignToDER(rawSign);
            System.out.println("2) SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));

            // --------------------------------服务端--------------------------------
            // 3，client的公钥验签
            boolean flag = SM2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
            sign = SM2Util.sign(priKey, SRC_DATA);
            System.out.println("3) SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));

            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 加解密测试
     */
    @Test
    public void testEncryptAndDecrypt() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            // --------------------------------客户端--------------------------------
            // 拿server的公钥加密
            byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));

            // --------------------------------服务端--------------------------------
            // 拿server的私钥解密
            byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 生成导出各种秘钥文件
     */
    @Test
    public void testKeyPairEncoding() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] priKeyPkcs8Der = BCECUtil.convertECPrivateKeyToPKCS8(priKey, pubKey);
            System.out.println("private key pkcs8 der length:" + priKeyPkcs8Der.length);
            System.out.println("private key pkcs8 der:" + ByteUtils.toHexString(priKeyPkcs8Der));
            FileUtil.writeFile("D:/ec.pkcs8.pri.der", priKeyPkcs8Der);

            String priKeyPkcs8Pem = BCECUtil.convertECPrivateKeyPKCS8ToPEM(priKeyPkcs8Der);
            FileUtil.writeFile("D:/ec.pkcs8.pri.pem", priKeyPkcs8Pem.getBytes("UTF-8"));
            byte[] priKeyFromPem = BCECUtil.convertECPrivateKeyPEMToPKCS8(priKeyPkcs8Pem);
            if (!Arrays.equals(priKeyFromPem, priKeyPkcs8Der)) {
                throw new Exception("priKeyFromPem != priKeyPkcs8Der");
            }

            BCECPrivateKey newPriKey = BCECUtil.convertPKCS8ToECPrivateKey(priKeyPkcs8Der);

            byte[] priKeyPkcs1Der = BCECUtil.convertECPrivateKeyToSEC1(priKey, pubKey);
            System.out.println("private key pkcs1 der length:" + priKeyPkcs1Der.length);
            System.out.println("private key pkcs1 der:" + ByteUtils.toHexString(priKeyPkcs1Der));
            FileUtil.writeFile("D:/ec.pkcs1.pri", priKeyPkcs1Der);

            byte[] pubKeyX509Der = BCECUtil.convertECPublicKeyToX509(pubKey);
            System.out.println("public key der length:" + pubKeyX509Der.length);
            System.out.println("public key der:" + ByteUtils.toHexString(pubKeyX509Der));
            FileUtil.writeFile("D:/ec.x509.pub.der", pubKeyX509Der);

            String pubKeyX509Pem = BCECUtil.convertECPublicKeyX509ToPEM(pubKeyX509Der);
            FileUtil.writeFile("D:/ec.x509.pub.pem", pubKeyX509Pem.getBytes("UTF-8"));
            byte[] pubKeyFromPem = BCECUtil.convertECPublicKeyPEMToX509(pubKeyX509Pem);
            if (!Arrays.equals(pubKeyFromPem, pubKeyX509Der)) {
                throw new Exception("pubKeyFromPem != pubKeyX509Der");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 公私钥（十六进制）转公私钥对象
     */
    @Test
    public void testSM2KeyRecovery() {
        try {
            String priHex = "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D";
            String xHex = "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913";
            String yHex = "F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String encodedPubHex = "04FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String signHex = "30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801";
            byte[] signBytes = ByteUtils.fromHexString(signHex);
            byte[] src = ByteUtils.fromHexString("0102030405060708010203040506070801020304050607080102030405060708");
            byte[] withId = ByteUtils.fromHexString("31323334353637383132333435363738");

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                new BigInteger(ByteUtils.fromHexString(priHex)), SM2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

            if (!SM2Util.verify(pubKey, src, signBytes)) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 生成公私钥（十六进制）
     */
    @Test
    public void testSM2KeyGen2() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * DER编码C1C2C3密文
     */
    @Test
    public void testEncodeSM2CipherToDER() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA);

            byte[] derCipher = SM2Util.encodeSM2CipherToDER(encryptedData);
            FileUtil.writeFile("derCipher.dat", derCipher);

            byte[] decryptedData = SM2Util.decrypt(priKey, SM2Util.decodeDERSM2Cipher(derCipher));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 生成BCEC公私钥
     */
    @Test
    public void testGenerateBCECKeyPair() {
        try {
            KeyPair keyPair = SM2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = BCECUtil.convertPrivateKeyToParameters((BCECPrivateKey) keyPair.getPrivate());
            ECPublicKeyParameters pubKey = BCECUtil.convertPublicKeyToParameters((BCECPublicKey) keyPair.getPublic());

            byte[] sign = SM2Util.sign(priKey, WITH_ID, SRC_DATA);
            boolean flag = SM2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            sign = SM2Util.sign(priKey, SRC_DATA);
            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
