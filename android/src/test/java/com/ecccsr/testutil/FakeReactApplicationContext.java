package com.ecccsr.testutil;

import android.content.Context;

import com.facebook.react.bridge.CatalystInstance;
import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.JavaScriptModule;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder;

import java.util.Collections;

/**
 * Minimal ReactApplicationContext for unit tests. Delegates Context methods (getFilesDir,
 * getPackageManager, etc.) to the real Robolectric application context via ContextWrapper, and
 * stubs the bridge-only abstract methods that CSRModule never calls.
 */
public class FakeReactApplicationContext extends ReactApplicationContext {

    public FakeReactApplicationContext(Context base) {
        super(base);
    }

    @Override
    public <T extends JavaScriptModule> T getJSModule(Class<T> jsInterface) {
        throw new UnsupportedOperationException("Not used by CSRModule");
    }

    @Override
    public <T extends NativeModule> boolean hasNativeModule(Class<T> nativeModuleInterface) {
        return false;
    }

    @Override
    public java.util.Collection<NativeModule> getNativeModules() {
        return Collections.emptyList();
    }

    @Override
    public <T extends NativeModule> T getNativeModule(Class<T> nativeModuleInterface) {
        return null;
    }

    @Override
    public NativeModule getNativeModule(String name) {
        return null;
    }

    @Override
    public CatalystInstance getCatalystInstance() {
        throw new UnsupportedOperationException("Not used by CSRModule");
    }

    @Override
    public boolean hasActiveCatalystInstance() {
        return false;
    }

    @Override
    public boolean hasActiveReactInstance() {
        return false;
    }

    @Override
    public boolean hasCatalystInstance() {
        return false;
    }

    @Override
    public boolean hasReactInstance() {
        return false;
    }

    @Override
    public void destroy() {
        // no-op
    }

    @Override
    public void handleException(Exception e) {
        throw new RuntimeException(e);
    }

    @Override
    public boolean isBridgeless() {
        return false;
    }

    @Override
    public JavaScriptContextHolder getJavaScriptContextHolder() {
        return null;
    }

    @Override
    public CallInvokerHolder getJSCallInvokerHolder() {
        throw new UnsupportedOperationException("Not used by CSRModule");
    }

    @Override
    public UIManager getFabricUIManager() {
        return null;
    }

    @Override
    public String getSourceURL() {
        return null;
    }

    @Override
    public void registerSegment(int segmentId, String path, com.facebook.react.bridge.Callback callback) {
        // no-op
    }
}
