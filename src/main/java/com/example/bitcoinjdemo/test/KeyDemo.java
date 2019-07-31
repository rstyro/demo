package com.example.bitcoinjdemo.test;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.DeterministicSeed;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKMULTISIG;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKSIG;

public class KeyDemo {
    public static void main(String[] args) throws Exception {
//        genKey();
//        p2pkh();
//        p2sh();
//        multiSig();
        testbip44();
    }

    public static void test(){
        NetworkParameters networkParameters = null;
//        networkParameters = TestNet3Params.get(); // 公共测试网络
//        networkParameters = RegTestParams.get(); // 私有测试网络
        networkParameters = MainNetParams.get(); // 生产网络
        ECKey ceKey = new ECKey();

        BigInteger privKey = ceKey.getPrivKey();// 私钥， BigInteger
        String privateKeyAsHex = ceKey.getPrivateKeyAsHex();// 私钥， Hex
        System.out.println("privateKeyAsHex:"+privateKeyAsHex);
        String privateKeyAsWiF = ceKey.getPrivateKeyAsWiF(networkParameters);// 私钥， WIF(Wallet Import Format)
        System.out.println(privateKeyAsWiF);
        ceKey.getPrivKeyBytes(); // 私钥 byte[]



        String publicKeyAsHex = ceKey.getPublicKeyAsHex();// 公钥Hex
        System.out.println(publicKeyAsHex);
        ceKey.getPubKey(); // 公钥原始字节数组byte[]

        Address address = ceKey.toAddress(networkParameters);
        System.out.println(address.toBase58().toString());
    }

    /**
     * 获取助记词
     * @return
     * @throws Exception
     */
    public static List<String>  getKeyWordList() throws Exception {
        //随机熵
        SecureRandom rand = new SecureRandom();
        // 4的倍数
        byte[] entropy = new byte[16];
        rand.nextBytes(entropy);
        //熵转化为助记词
        MnemonicCode mc = new MnemonicCode();
        List<String> mnemonic = mc.toMnemonic(entropy);
        return mnemonic;
    }

    public static void genKey() throws Exception {
        String[] seeds = "ring, ticket, solar, culture, carbon, print, wonder, nut, bundle, flame, submit, hundred".split(",");
        List<String> mnemonic =Arrays.asList(seeds);
//        List<String> mnemonic = getKeyWordList();
        System.out.println(mnemonic.toString());

        //助记词转化为种子
        String pass = "7878";
        byte[] seed = MnemonicCode.toSeed(mnemonic,pass);
        //生成主密钥
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seed);
        System.out.println(masterKey.toString());

        //子密钥
        DeterministicKey key = HDKeyDerivation.deriveChildKey(masterKey,1);
        System.out.format("child#7878 priv => %s\n",key.getPrivateKeyAsHex());
        System.out.format("child#7878 pub => %s\n", key.getPublicKeyAsHex());



        DeterministicKey masterPubKey = masterKey.dropPrivateBytes();
        DeterministicKey key1 = HDKeyDerivation.deriveChildKey(masterPubKey,1);
        System.out.format("child#7878 pub => %s\n", key1.getPublicKeyAsHex());


        NetworkParameters params = RegTestParams.get();
        String xprv = key.serializePrivB58(params);
        String xpub = key.serializePubB58(params);
        System.out.println(xprv);
        System.out.println(xpub);

        //恢复
        DeterministicKey prvKey = DeterministicKey.deserializeB58(xprv,params);
        System.out.println(prvKey.toString()+",prv="+prvKey.getPrivateKeyAsHex());

        //强化密钥
        int id = 123;
        DeterministicKey normalKey = HDKeyDerivation.deriveChildKey(masterKey,id);
        DeterministicKey hardenedKey = HDKeyDerivation.deriveChildKey(masterKey,id | 0x80000000);

        System.out.println(normalKey.getPrivateKeyAsHex()+","+normalKey.getPublicKeyAsHex());
        System.out.println(hardenedKey.getPrivateKeyAsHex()+","+hardenedKey.getPublicKeyAsHex());

        //实例化一个ChildNumber对象来指明是否强化密钥
        DeterministicKey normalKey1 = HDKeyDerivation.deriveChildKey(masterKey,new ChildNumber(123,false));
        DeterministicKey hardenedKey1 = HDKeyDerivation.deriveChildKey(masterKey,new ChildNumber(123,true));

        System.out.println(normalKey1.getPrivateKeyAsHex()+","+normalKey1.getPublicKeyAsHex());
        System.out.println(hardenedKey1.getPrivateKeyAsHex()+","+hardenedKey1.getPublicKeyAsHex());
        path(masterKey);
    }

    public static void testbip44() throws Exception {
//        List<String> mnemonic = getKeyWordList();
        String[] seeds = "ring, ticket, solar, culture, carbon, print, wonder, nut, bundle, flame, submit, hundred".split(",");
        List<String> mnemonic =Arrays.asList(seeds);
        System.out.println("mnemonic="+mnemonic);

        String pass = "123456";
        byte[] seed = MnemonicCode.toSeed(mnemonic,pass);
        //生成主密钥
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seed);
        System.out.println("masterKey="+masterKey.getPrivateKeyAsHex());
        System.out.println("masterKey="+masterKey.getPublicKeyAsHex());

        //子密钥
//        for (int i = 0; i < 20; i++) {
//            DeterministicKey childKey = HDKeyDerivation.deriveChildKey(masterKey,i);
//            System.out.format("child#7878 priv => %s\n",childKey.getPrivateKeyAsHex());
//            System.out.format("child#7878 pub => %s\n", childKey.getPublicKeyAsHex());
//            System.out.println();
//        }

        System.out.println("========================");
        DeterministicHierarchy hd = new DeterministicHierarchy(masterKey);
        for (int i = 0; i < 20; i++) {
            String path = "M/44/0/0/0/"+i;
            List<ChildNumber> cnl = HDUtils.parsePath(path);
            DeterministicKey key = hd.get(cnl,true,true);
            System.out.println("path="+key.getPrivateKeyAsHex());
            System.out.println("path="+key.getPublicKeyAsHex());
            Address address = key.toAddress(MainNetParams.get());
            System.out.println("address="+address.toBase58());
            System.out.println();
        }
    }

    /**
     * m / purpose' / coin' / account' / change / address_index
     * m是固定的, Purpose也是固定的，值为44（或者 0x8000002C）
     * Coin type 这个代表的是币种，0代表比特币，1代表比特币测试链，60代表以太坊
     * Account 代表这个币的账户索引，从0开始
     * Change 常量0用于外部链，常量1用于内部链（也称为更改地址）。外部链用于在钱包外可见的地址（例如，用于接收付款）。内部链用于在钱包外部不可见的地址，用于返回交易变更。 (所以一般使用0)
     * address_inde 这就是地址索引，从0开始，代表生成第几个地址，官方建议，每个account下的address_index不要超过20
     * @param masterKey
     */
    public static void path(DeterministicKey masterKey){
        DeterministicHierarchy hd = new DeterministicHierarchy(masterKey);
        String path = "M/44/0/0/0/3";
        List<ChildNumber> cnl = HDUtils.parsePath(path);
        DeterministicKey key = hd.get(cnl,true,true);
        System.out.println("path="+key.toString());
    }

    public static void p2pkh(){
        NetworkParameters params = MainNetParams.get();
        ECKey key = new ECKey();
        Address addr = new Address(params,key.getPubKeyHash());
        System.out.format("p2pkh address => %s\n",addr.toString());
    }

    public static void p2sh(){
        NetworkParameters params = MainNetParams.get();
        ECKey key = new ECKey();
        Script redeemScript = (new ScriptBuilder()).data(key.getPubKey()).op(OP_CHECKSIG).build();
        byte[] hash = Utils.sha256hash160(redeemScript.getProgram());
        Address addr = Address.fromP2SHHash(params,hash);
        System.out.format("p2sh address => %s\n",addr.toString());


    }

    public static void multiSig(){
        NetworkParameters params = RegTestParams.get();
        List<ECKey> keys = Arrays.asList(new ECKey(),new ECKey());
        Script redeemScript = ScriptBuilder.createMultiSigOutputScript(2,keys);
        Script p2shOutputScript = ScriptBuilder.createP2SHOutputScript(redeemScript);
        Address addr = p2shOutputScript.getToAddress(params);
        System.out.format("p2sh msig address => %s\n",addr);
    }


}
