package com.example.bitcoinjdemo.test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicHierarchy;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.HDUtils;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HDWalletPK {

    private static Logger LOG = LoggerFactory.getLogger(HDWalletPK.class);

    static NetworkParameters params;

    static{
        try {
//            Configuration config = ConfigUtil.getInstance();
//            params = config.getBoolean("bitcoin.testnet") ? TestNet3Params.get() : MainNetParams.get();
            params = TestNet3Params.get();
            LOG.info("=== [BTC] bitcoin  client networkID：{} ===",params.getId());
        } catch (Exception e) {
            LOG.info("=== [BTC] com.bscoin.coldwallet.cointype.btc.HDWalletPK:{} ===",e.getMessage(),e);
        }
    }


    /**
     * @throws IOException
     * @throws FileNotFoundException
     * @Title: createHDWalletByPATH
     * @param @param word 助记词
     * @param @param passphrase 密码
     * @param @param childNum 生成的hd钱包数量
     * @param @param params
     * @param @return    参数
     * @return List<HDWallet>    返回类型
     * @throws
     */
    public static List<HDWallet> createHDWalletByPATH(String word, String passphrase, int[] childNum) throws FileNotFoundException, IOException {
        List<HDWallet> wallet = new ArrayList<HDWallet>();
        try {
            DeterministicSeed deterministicSeed = new DeterministicSeed(word, null, passphrase, 0L);
            DeterministicKeyChain deterministicKeyChain = DeterministicKeyChain.builder().seed(deterministicSeed).build();
            DeterministicKey main = deterministicKeyChain.getKeyByPath(HDUtils.parsePath("44H/0H"), true);
            DeterministicHierarchy tree = new DeterministicHierarchy(main);
            DeterministicKey rootKey = tree.getRootKey();
            LOG.info("### [BTC] childs privKey , pubKey , address start ###");
            for (int i = childNum[0], len = childNum[1]; i < len; i++) {
                DeterministicKey deriveChildKey = HDKeyDerivation.deriveChildKey(rootKey, new ChildNumber(i));
                wallet.add(new HDWallet(deriveChildKey.getPathAsString(),
                        deriveChildKey.getPrivateKeyAsWiF(params),
                        Base58.encode(deriveChildKey.getPubKey()),
                        ECKey.fromPrivate(deriveChildKey.getPrivKey()).toAddress(params).toBase58()));
            }

            LOG.info("### [BTC] childs privKey , pubKey , address end ###");
        } catch (UnreadableWalletException e) {
            e.printStackTrace();
        }
        return wallet;
    }


    /**
     * @Title: generateMnemonic
     * @param @param passphrase
     * @param @param params
     * @param @return
     * @param @throws IOException    参数
     * @return String    返回类型
     * @throws
     */
    public static String generateMnemonic(String passphrase) throws IOException {
        StringBuilder words = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();
        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        DeterministicSeed ds = new DeterministicSeed(secureRandom, 128, passphrase, creationTimeSeconds);

        for (String str : ds.getMnemonicCode()) {
            words.append(str).append(" ");
        }
        return words.toString().trim();
    }



    /**
     * @Title: generateAddress   根据公钥生成地址
     * @param @param publicKey
     * @param @return    参数
     * @return String    返回类型
     * @throws
     */
    public static String generateAddress(String publicKey) {
        //1. 计算公钥的 SHA-256 哈希值
        byte[] sha256Bytes = HashUtils.sha256(Base58.decode(publicKey));
        //2. 取上一步结果，计算 RIPEMD-160 哈希值
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256Bytes, 0, sha256Bytes.length);
        byte[] ripemd160Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(ripemd160Bytes, 0);
        //3. 取上一步结果，前面加入地址版本号（主网版本号“0x00”）
        byte[] networkID = new BigInteger("00", 16).toByteArray();
        byte[] extendedRipemd160Bytes = HashUtils.add(networkID, ripemd160Bytes);
        //4. 取上一步结果，计算 SHA-256 哈希值
        byte[] oneceSha256Bytes = HashUtils.sha256(extendedRipemd160Bytes);
        //5. 取上一步结果，再计算一下 SHA-256 哈希值
        byte[] twiceSha256Bytes = HashUtils.sha256(oneceSha256Bytes);
        //6. 取上一步结果的前4个字节（8位十六进制）
        byte[] checksum = new byte[4];
        System.arraycopy(twiceSha256Bytes, 0, checksum, 0, 4);
        //7. 把这4个字节加在第5步的结果后面，作为校验
        byte[] binaryAddressBytes = HashUtils.add(extendedRipemd160Bytes, checksum);
        //8. 把结果用 Base58 编码算法进行一次编码
        return Base58.encode(binaryAddressBytes);
    }

    /**
     * 验证地址是否合法
     * @param address
     * @return
     */
    public static boolean verifyAddress(String address) {
        if (address.length() < 26 || address.length() > 35) {
            return false;
        }
        byte[] decoded = HashUtils.decodeBase58To25Bytes(address);
        if (null == decoded) {
            return false;
        }
        // 验证校验码
        byte[] hash1 = HashUtils.sha256(Arrays.copyOfRange(decoded, 0, 21));
        byte[] hash2 = HashUtils.sha256(hash1);

        return Arrays.equals(Arrays.copyOfRange(hash2, 0, 4), Arrays.copyOfRange(decoded, 21, 25));
    }

    public static void main(String[] args) throws IOException {
        String s = generateMnemonic("xx");//生成助记次
        System.out.println(s);
        s= "play risk guide hour lion slot stadium spin unusual check month army";
        int[] a = {1,10};//根据助记词生成childID={1-10}的钱包地址
        List<HDWallet> walls = createHDWalletByPATH(s, "123457",a);
        for (HDWallet hdWallet : walls) {
            System.out.println(hdWallet.getPubKey());
            System.out.println(hdWallet.getPrivKey());
            System.out.println(hdWallet.getAddress());
            System.out.println(hdWallet.toString());
            System.out.println("----------------------");
        }
    }
}
