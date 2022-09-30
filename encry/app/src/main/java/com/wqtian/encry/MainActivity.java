package com.wqtian.encry;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import android.util.Log;
import android.view.View;

import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import okio.ByteString;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "Encry";

    private static final String data = "wqtian";
    private static final String SECRET_KEY = "1234567890abcdef";

    /*
        DES KEY 和 IV 向量 长度都必须 8 个字节
     */
    private static final String DES_KEY = "12345678";
    private static final String IV = "12345678";

    /*
        16/24 个字节长度
     */
    private static final String DESede_KEY = "123456781234567812345678";

    /*
        16/24/32 个字节长度
     */
    private static final String AES_KEY = "0123456789abcdef";

    private static final String RSA_PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMOVkFb2U8aOxLZr\n" +
            "v/R/Vq/8+vB1fp4GnLLmBhH/g343Q5J6/9AVqbflgf9DRgzP/zBUoauRQnvfsUBt\n" +
            "6NXKv3t2bkkAkA4ulCqk6+pxW/Zy03LyyADUtkBrDrTfGHqaw6vJSp0qjT56u563\n" +
            "V0nOoUboUmj+AIZRrzNEcwAKa7B1AgMBAAECgYB4oflDCe+mGkzOTys4PIpVRe3o\n" +
            "/i84fM+NsD6yPyz1XlS5NlAuIg5qNI63yOCd6nR1dN26mn+tM8159dCUfNcY1W3F\n" +
            "JaTvBZKD5+6fDUKQ5UfHhlrd4rVxWKK+kuhdYe67/Y6twrMzL/TE+OXmn7jdxuq2\n" +
            "Au93oa2kxraM6pGJCQJBAN/P+ckCGRl26UraqzP3XwrVPq+yGQUMb8y627MXwVJJ\n" +
            "LsE3c9vuoDkm79rYN8jCXbxSkUbBpxopHYfdSxT/Dt8CQQDftlI8PZXDzJLlJAmm\n" +
            "LynoC7OO52sdC+PoqndJ04DDjo1rg6fcWaaIXFmOL/WTn5HJt8pa4r7vi54DChZ7\n" +
            "ju8rAkBUBUSVdGctyxk7k6mv4Y7Zh0J4PNjtr0SNTBzMN//IP1cBDCs/hm655ecn\n" +
            "dgJDKMx9tVV6hZqQ1JyUc7wLDtFrAkB1s6ZmvXw7jTnIR4KwJeZliSqKyGVJ3gSm\n" +
            "WHH0rMv1l93+MEG0JJMC8ZvIvKD3b6Azwng8A0q0HAAh1z/m+FgLAkEA0PahyHnX\n" +
            "ZCzB5ic4QvkiKCqZ+SyibYXOGxBGyCXkuirCwqrtaEorrFxgNEssdpHcEmk71+nv\n" +
            "gvrL5QkvgcLvMA==";

    private static final String RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDlZBW9lPGjsS2a7/0f1av/Prw\n" +
            "dX6eBpyy5gYR/4N+N0OSev/QFam35YH/Q0YMz/8wVKGrkUJ737FAbejVyr97dm5J\n" +
            "AJAOLpQqpOvqcVv2ctNy8sgA1LZAaw603xh6msOryUqdKo0+eruet1dJzqFG6FJo\n" +
            "/gCGUa8zRHMACmuwdQIDAQAB";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        final ScrollView scrollView = new ScrollView(this);
        setContentView(scrollView);

        final LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        scrollView.addView(layout);

        /*
            从字符串到 hex

            Hex 编码是一种用 16 个字符 (0-9 a-f) 表示任意二进制数据的方法！
            它是一种编码，而非加密！
            Hex 主要应用在 MD5 等加密表现形式上。
         */
        addButton("Hex", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
                ByteString of = ByteString.of(bytes);
                String hex = of.hex();
                Log.d(TAG, "hex:" + hex);
            }
        }, layout);

        /*
            Base64 是一种用 64 个字符 (A-Z a-z 0-9 + / =) 表示任意二进制数据的方法。

            它是一种编码，而非加密。
            像图片，,长密文甚至文件，都采用 Base64，因为可承载的数据很多！
         */
        addButton("Base64", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                //从字符串到base64
                byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
                ByteString of = ByteString.of(bytes);
                
                //方式一
                String base64 = of.base64();
                Log.d(TAG, "base64_1:" + base64);
                
                //方式二
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    String s = Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
                    byte[] encode = Base64.getEncoder().encode(data.getBytes(StandardCharsets.UTF_8));
                    Log.d(TAG, "base64_2:" + s);
                    Log.d(TAG, "base64_2:" + new String(encode));
                }
                
                //方式三
                String s = android.util.Base64.encodeToString(data.getBytes(StandardCharsets.UTF_8),0);
                Log.d(TAG, "base64_3:" + s);
            }
        }, layout);

        /*
            消息摘要算法包括 MD系列、SHA系列、MAC系列。其最主要的特征:

            1.密文是不可逆的！
                就是说,我在客户端把密码通过 md5 加密了，服务端也得采用相同的方式加密，进行比较。

            2.不定长度输入，固定长度输出
                就是说，不管是 123，还是 123456... 经过加密，加密的结果都是固定的长度！

            3.加密结果唯一！
         */

        /*
            MD5

            在 update 时压入数据，通过 digest 获得加密结果，md5 一般通过 hex 展示加密结果！

            MD 系列算法
            算法	摘要长度	实现
            MD2	128	    Java6
            MD5	128	    Java6
            MD5	128	    Bouncy Castle
         */
        addButton("MD5", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                MessageDigest md5 = null;
                try {
                    md5 = MessageDigest.getInstance("MD5");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    return;
                }
                //1. md5加密的数据可以直接放在digest中
                //2. digest是加密之后的数据,但是有不可见字符
                md5.update(data.getBytes(StandardCharsets.UTF_8));
                byte[] digest = md5.digest();

                //1. 效果完全同上,update可以压入数据,区别是 digest 是一次性压入, update 可以分批次压入
                //byte[] digest = md5.digest(data.getBytes(StandardCharsets.UTF_8));

                //使用 hex 和 base64来表示加密之后的数据,因为直接加密的有不可见字符
                ByteString of = ByteString.of(digest);
                String hex = of.hex();
                String base64 = of.base64();
                Log.d(TAG,"MD5: " + hex + "||" + base64);
            }
        }, layout);

        /*
            SHA

            常用的是 sha-256 算法,甚至来说消息摘要算法基本上 api 都是通用的。
            只需要换一个 algorithm 即可。

            算法	    摘要长度	实现
            SHA-1	160	    Java6
            SHA-256	256	    Java6
            SHA-384	384	    Java6
            SHA-512	512	    Java6
            SHA-224	224	    Bouncy Castle
         */
        addButton("SHA", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                MessageDigest sha256 = null;
                try {
                    sha256 = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    return;
                }
                sha256.update(data.getBytes(StandardCharsets.UTF_8));
                byte[] digest = sha256.digest();
                Log.d(TAG, "SHA 256 digest length: "+digest.length);

                ByteString of = ByteString.of(digest);
                String hex = of.hex();
                String base64 = of.base64();
                Log.d(TAG,"SHA: " + hex + "||" + base64);
            }
        },layout);

        /*
            MAC

            就是比 md5 和 sha 算法多了个密钥而已

            MAC系列算法
            算法	     消息摘要长度	实现
            HmacMD5	    128	    Java6
            HmacSHA1	160	    Java6
            HmacSHA256	256	    Java6
            HmacSHA384	384	    Java6
            HmacSHA512	512	    Java6
            HmacMD2	    128	    Java6
            HmacMD4	    128	    Bouncy Castle
            HmacSHA224	224	    Bouncy Castle
         */
        addButton("MAC", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                //生成密钥
                SecretKeySpec hmacMD5 = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "HmacMD5");

                //hmacMD5.getAlgorithm()表示获取算法,此时获取的就是HmacMD5
                Mac instance = null;
                try {
                    instance = Mac.getInstance(hmacMD5.getAlgorithm());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                //同上
                //Mac instance = Mac.getInstance("HmacMD5");

                //初始化
                try {
                    instance.init(hmacMD5);
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }
                //压入数据
                instance.update(data.getBytes(StandardCharsets.UTF_8));
                byte[] doFinal = instance.doFinal();

                //同上
                //byte[] doFinal = instance.doFinal(data.getBytes(StandardCharsets.UTF_8));

                ByteString of = ByteString.of(doFinal);
                String hex = of.hex();
                String base64 = of.base64();

                Log.d(TAG,"MAC: " + hex + "||" + base64);
            }
        }, layout);

        /*
            对称加密算法

            加密和解密使用的密钥相同。对称加密算法的密钥的内容可以随意设置，但有长度要求

            各算法密钥长度：
            RC4 密钥长度 1~256 字节
            DES 密钥长度 8 字节
            3DES/DESede/TripleDES 密钥长度 24 字节
            AES 密钥长度 16,24,32 字节，根据密钥长度不同 AES 又分为 AES-128，AES-192，AES-256
         */

        /*
            DES

            存在 ECB、CBC两种模式，其差别在于 CBC 模式需要一个 iv 向量

            具体内容查看 ../../../../../../img/DES.png
         */
        /*
            ECB 模式加解密
         */
        addButton("DES-ECB", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                byte[] doFinal = new byte[0];
                try {
                    doFinal = desEncryptECB(data);
                    ByteString of = ByteString.of(doFinal);
                    String hex = of.hex();
                    String base64 = of.base64();
                    Log.d(TAG, "DES-ECB encry result: "+ hex + "||" + base64);
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }

                try {
                    String result = desDecryptECB(doFinal);
                    assert(result.contentEquals(data));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, layout);

        /*
            CBC 模式加解密
         */
        addButton("DES-CBC", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                byte[] doFinal = new byte[0];
                try {
                    doFinal = desEncryptCBC(data);
                    ByteString of = ByteString.of(doFinal);
                    String hex = of.hex();
                    String base64 = of.base64();
                    Log.d(TAG, "DES-CBC encry result: "+ hex + "||" + base64);
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }

                try {
                    String result = desDecryptCBC(doFinal);
                    assert(result.contentEquals(data));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, layout);

        /*
            DESede(3DES/TripleDES)

            DESede 也分 CBC 和 ECB,使用方法同 DES

            具体内容查看 ../../../../../../img/DESede.png
         */
        addButton("DESede-CBC", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                byte[] doFinal = new byte[0];
                try {
                    doFinal = desedeEncrypt(data);
                    ByteString of = ByteString.of(doFinal);
                    String hex = of.hex();
                    String base64 = of.base64();
                    Log.d(TAG, "DESede-CBC encry result: "+ hex + "||" + base64);
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    String result = desedeDecrypt(doFinal);
                    assert(result.contentEquals(data));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, layout);

        /*
            AES

            AES 也分 CBC 和 ECB,使用方法同 DES

            具体内容查看 ../../../../../../img/AES.png
         */
        addButton("AES-ECB", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                byte[] doFinal = new byte[0];
                try {
                    doFinal = aesEncrypt(data);
                    ByteString of = ByteString.of(doFinal);
                    String hex = of.hex();
                    String base64 = of.base64();
                    Log.d(TAG, "AES-ECB encry result: "+ hex + "||" + base64);
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    String result = aesDecrypt(doFinal);
                    assert(result.contentEquals(data));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, layout);

        /*
            非对称加密算法

            非对称加密算法中，最常用最典型的加密算法就是 RSA。原来说过，对称加密算法是因为加密解密用的是同一个密钥，但是非对称就不是了。
            它需要一对，称为公钥和私钥，当然，密钥不是随便写的！
            在线密钥生成网站:http://web.chacuo.net/netrsakeypair

            公钥加密，私钥解密。
            私钥加密，公钥解密。

            一般公钥是公开的，私钥保密，私钥包含公钥。
            加密安全，但是性能差，加密长度有限制。

            RSA 可以用于加密解密，也可以用来数据签名。

            Java 中的私钥必须是 pkcs8 格式。
         */

        /*
            RSA

            具体内容查看 ../../../../../../img/RSA.png
         */
        addButton("RSA-公钥加密-私钥解密", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                //加密
                String rsaPublicEncrypt = null;
                try {
                    rsaPublicEncrypt = rsaPublicEncrypt(data);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                Log.d(TAG, "RSA 公钥加密结果: " + rsaPublicEncrypt);

                //解密
                byte[] bytes5 = ByteString.decodeBase64(rsaPublicEncrypt).toByteArray();
                String rsaPrivateDecrypt = null;
                try {
                    rsaPrivateDecrypt = rsaPrivateDecrypt(bytes5);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                assert(rsaPrivateDecrypt.contentEquals(data));
                Log.d(TAG, "RSA 私钥解密结果: " + rsaPrivateDecrypt);
            }
        }, layout);

        addButton("RSA-私钥加密-公钥解密", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                //加密
                String rsaEncrypt = null;
                try {
                    rsaEncrypt = rsaPrivateEncrypt(data);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                Log.d(TAG, "RSA 私钥加密结果: " + rsaEncrypt);

                //解密
                byte[] bytes5 = ByteString.decodeBase64(rsaEncrypt).toByteArray();
                String rsaDecrypt = null;
                try {
                    rsaDecrypt = rsaPublicDecrypt(bytes5);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                assert(rsaDecrypt.contentEquals(data));
                Log.d(TAG, "RSA 私钥解密结果: " + rsaDecrypt);
            }
        }, layout);
    }

    private void addButton(String text, View.OnClickListener clickListener, LinearLayout layout) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setOnClickListener(clickListener);
        layout.addView(btn);
    }

    //DES ECB 加密
    private static byte[] desEncryptECB(String data) throws BadPaddingException, IllegalBlockSizeException {
        //生成des所需要的key
        SecretKeySpec desKey = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        //默认工作模式就是ECB,填充模式PKCS5Padding,
        //Cipher instance = Cipher.getInstance("DES");
        //也可以写全
        Cipher instance = null;
        try {
            instance = Cipher.getInstance("DES/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        //初始化,指定是加密模式还是解密模式和密钥
        try {
            instance.init(Cipher.ENCRYPT_MODE, desKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        //关于Cipher的update似乎有些问题,所以用doFinal的多
        //加密内容,返回结果
        return instance.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    //DES ECB 解密
    private static String desDecryptECB(byte[] cipherBytes) throws Exception {
        //生成des所需要的key
        SecretKeySpec desKey = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        Cipher instance = Cipher.getInstance("DES/ECB/PKCS5Padding");
        instance.init(Cipher.DECRYPT_MODE, desKey);
        byte[] doFinal = instance.doFinal(cipherBytes);
        return new String(doFinal);
    }

    //DES CBC 加密
    private static byte[] desEncryptCBC(String data) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecretKeySpec desKey = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        Cipher instance = Cipher.getInstance("DES/CBC/PKCS5Padding");
        //CBC需要iv向量
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
        //初始化时添加上iv向量
        instance.init(Cipher.ENCRYPT_MODE, desKey,ivParameterSpec);
        return instance.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    //DES CBC 解密
    private static String desDecryptCBC(byte[] cipherBytes) throws Exception {
        SecretKeySpec desKey = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        Cipher instance = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
        instance.init(Cipher.DECRYPT_MODE, desKey,ivParameterSpec);
        byte[] doFinal = instance.doFinal(cipherBytes);
        return new String(doFinal);
    }


    private static byte[] desedeEncrypt(String plainText) throws Exception {
        SecretKeySpec desKey = new SecretKeySpec(DESede_KEY.getBytes(), "DESede");
        //ECB模式
        //        Cipher instance = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        //        instance.init(Cipher.ENCRYPT_MODE, desKey);
        //        byte[] doFinal = instance.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        //CBC模式需要iv向量
        Cipher instance = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
        //初始化时添加上iv向量
        instance.init(Cipher.ENCRYPT_MODE, desKey, ivParameterSpec);
        return instance.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    //DESede
    private static String desedeDecrypt(byte[] cipherBytes) throws Exception {
        //生成des所需要的key
        SecretKeySpec desKey = new SecretKeySpec(DESede_KEY.getBytes(StandardCharsets.UTF_8), "DESede");
        //ECB模式
        //        Cipher instance = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        //        instance.init(Cipher.DECRYPT_MODE, desKey);
        //        byte[] doFinal = instance.doFinal(cipherBytes);

        //CBC模式
        Cipher instance = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
        instance.init(Cipher.DECRYPT_MODE, desKey,ivParameterSpec);
        byte[] doFinal = instance.doFinal(cipherBytes);
        return new String(doFinal);
    }


    private static byte[] aesEncrypt(String plainText) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        //ECB模式
        Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
        instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return instance.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        //CBC模式需要iv向量
        //        Cipher instance = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        //        IvParameterSpec ivParameterSpec = new IvParameterSpec("12345678".getBytes());
        //        //初始化时添加上iv向量
        //        instance.init(Cipher.ENCRYPT_MODE, desKey, ivParameterSpec);
        //        byte[] doFinal = instance.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    private static String aesDecrypt(byte[] cipherBytes) throws Exception {
        //生成des所需要的key
        SecretKeySpec secretKeySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        //ECB模式
        Cipher instance = Cipher.getInstance("AES/ECB/PKCS5Padding");
        instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] doFinal = instance.doFinal(cipherBytes);

        //CBC模式
        //        Cipher instance = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        //        IvParameterSpec ivParameterSpec = new IvParameterSpec("12345678".getBytes());
        //        instance.init(Cipher.DECRYPT_MODE, desKey, ivParameterSpec);
        //        byte[] doFinal = instance.doFinal(cipherBytes);

        return new String(doFinal);
    }


    //RSA

    //解析公钥key并返回
    private static PublicKey generatePublic(String publicKeyBase64) throws Exception {
        byte[] bytes = ByteString.decodeBase64(publicKeyBase64).toByteArray();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    //解析私钥key并返回
    private static PrivateKey generatePrivate(String privateKeyBase64) throws Exception {
        byte[] bytes = ByteString.decodeBase64(privateKeyBase64).toByteArray();
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    //RSA 这里使用私钥解密
    private static String rsaPrivateDecrypt(byte[] cipherBytes) throws Exception {
        PrivateKey privateKey = generatePrivate(RSA_PRIVATE_KEY);
        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] doFinal = instance.doFinal(cipherBytes);

        return new String(doFinal);
    }

    //RSA 使用公钥加密
    private static String rsaPublicEncrypt(String plainText) throws Exception {
        PublicKey publicKey = generatePublic(RSA_PUBLIC_KEY);
        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] doFinal = instance.doFinal(plainText.getBytes());

        ByteString of = ByteString.of(doFinal);
        return of.base64();
    }

    //RSA 这里使用公钥解密
    public static String rsaPublicDecrypt(byte[] cipherBytes) throws Exception {
        PublicKey publicKey = generatePublic(RSA_PUBLIC_KEY);
        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] doFinal = instance.doFinal(cipherBytes);

        return new String(doFinal);
    }

    //RSA 使用私钥加密
    private static String rsaPrivateEncrypt(String plainText) throws Exception {
        PrivateKey privateKey = generatePrivate(RSA_PRIVATE_KEY);
        Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        instance.init(Cipher.ENCRYPT_MODE,privateKey);
        byte[] doFinal = instance.doFinal(plainText.getBytes());

        ByteString of = ByteString.of(doFinal);
        return of.base64();
    }
}