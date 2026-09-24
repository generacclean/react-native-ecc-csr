package com.ecccsr.testutil;

import com.ecccsr.CSRCore;

import java.util.Map;

/** Captures a single resolve/reject call so tests can assert on the outcome synchronously. */
public class RecordingPromise implements CSRCore.Reply {

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
    public void reject(String code, String message, Throwable throwable) {
        rejected = true;
        rejectedCode = code;
        rejectedMessage = message;
        rejectedThrowable = throwable;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> resolvedMap() {
        return (Map<String, Object>) resolvedValue;
    }
}
