package com.example.bitcoinjdemo.tran;

import lombok.Data;

import java.io.Serializable;

@Data
public class UnSpentUtxo implements Serializable {
    private static final long serialVersionUID = -7417428486644921613L;

    private String hash;//交易hash
    private long txN; //
    private long value;//金额
    private int height;//区块高度
    private String script;//hex
    private String address;//钱包地址
}
