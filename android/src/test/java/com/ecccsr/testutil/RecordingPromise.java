package com.ecccsr.testutil;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.WritableMap;

/** Captures a single resolve/reject call so tests can assert on the outcome synchronously. */
public class RecordingPromise implements Promise {

    public Object resolvedValue;
    public String rejectedCode;
    public String rejectedMessage;
    public Throwable rejectedThrowable;
    public boolean resolved = false;
    public boolean rejected = false;

    @Override
    public void resolve(Object value) {
        resolved = true;
        resolvedValue = value;
    }

    @Override
    public void reject(String code, String message) {
        rejected = true;
        rejectedCode = code;
        rejectedMessage = message;
    }

    @Override
    public void reject(String code, Throwable throwable) {
        rejected = true;
        rejectedCode = code;
        rejectedThrowable = throwable;
    }

    @Override
    public void reject(String code, String message, Throwable throwable) {
        rejected = true;
        rejectedCode = code;
        rejectedMessage = message;
        rejectedThrowable = throwable;
    }

    @Override
    public void reject(Throwable throwable) {
        rejected = true;
        rejectedThrowable = throwable;
    }

    @Override
    public void reject(Throwable throwable, WritableMap userInfo) {
        rejected = true;
        rejectedThrowable = throwable;
    }

    @Override
    public void reject(String code, WritableMap userInfo) {
        rejected = true;
        rejectedCode = code;
    }

    @Override
    public void reject(String code, Throwable throwable, WritableMap userInfo) {
        rejected = true;
        rejectedCode = code;
        rejectedThrowable = throwable;
    }

    @Override
    public void reject(String code, String message, WritableMap userInfo) {
        rejected = true;
        rejectedCode = code;
        rejectedMessage = message;
    }

    @Override
    public void reject(String code, String message, Throwable throwable, WritableMap userInfo) {
        rejected = true;
        rejectedCode = code;
        rejectedMessage = message;
        rejectedThrowable = throwable;
    }

    @Override
    public void reject(String message) {
        rejected = true;
        rejectedMessage = message;
    }

    public WritableMap resolvedMap() {
        return (WritableMap) resolvedValue;
    }
}
