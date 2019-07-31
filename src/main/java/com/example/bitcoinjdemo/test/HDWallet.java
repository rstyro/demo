package com.example.bitcoinjdemo.test;

import java.io.Serializable;

import org.bitcoinj.core.NetworkParameters;

public class HDWallet  implements Serializable{

    private static final long serialVersionUID = 1L;

    public HDWallet(){}

    public HDWallet(String path, String privKey, String pubKey, String address) {
        super();
        this.path = path;
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.address = address;
    }

    public HDWallet(String privKey, String pubKey, String address) {
        super();
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.address = address;
    }


    private String word; //助记词



    private String path;//路径-标识位
    private String passphrase;

    private String privKey; //私钥
    private String pubKey; //公钥

    private String address;//地址

    public String getWord() {
        return word;
    }
    public void setWord(String word) {
        this.word = word;
    }
    public String getPrivKey() {
        return privKey;
    }
    public void setPrivKey(String privKey) {
        this.privKey = privKey;
    }
    public String getPubKey() {
        return pubKey;
    }
    public void setPubKey(String pubKey) {
        this.pubKey = pubKey;
    }
    public String getAddress() {
        return address;
    }
    public void setAddress(String address) {
        this.address = address;
    }

    public String getPassphrase() {
        return passphrase;
    }
    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }
    public String getPath() {
        return path;
    }
    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public String toString() {
        return "HDWallet{" +
                "word='" + word + '\'' +
                ", path='" + path + '\'' +
                ", passphrase='" + passphrase + '\'' +
                ", privKey='" + privKey + '\'' +
                ", pubKey='" + pubKey + '\'' +
                ", address='" + address + '\'' +
                '}';
    }
}