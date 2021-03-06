package org.esec.mcg.androidu2fsimulator.token;

import android.app.ActivityManager;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import com.wepayplugin.nfcstd.WepayPlugin;

import org.esec.mcg.androidu2fsimulator.R;
import org.esec.mcg.androidu2fsimulator.token.impl.LocalU2FToken;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.RawMessageCodec;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.U2FTokenIntentType;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;
import org.json.JSONObject;

import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class U2FTokenActivity extends AppCompatActivity {

    public static final int SW_TEST_OF_PRESENCE_REQUIRED = 0x6985;
    public static final int SW_INVALID_KEY_HANDLE = 0x6a80;

    private U2FTokenIntentType u2fTokenIntentType;
    private AuthenticationRequest[] authenticationRequests;
    private RegistrationRequest registrationRequest;

    private U2FToken u2fToken;
    public static boolean USER_PRESENCE = false;
//    public static final Lock lock = new ReentrantLock();
//    public static Condition condition = lock.newCondition();
    static Object lock = new Object();
    static Object userPresenceLock = new Object();
    static boolean CHECKONLY_FINISHED = false;
    boolean illegal_intent = true;

    private RequestHandle requestHandle;
    private ResponseHandler responseHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_u2f_token);
        USER_PRESENCE = false;
        CHECKONLY_FINISHED = false;
        responseHandler = new ResponseHandler(this);
        u2fToken = new LocalU2FToken(this);
        Intent intent = getIntent();
        Bundle data;
        if ((data = intent.getBundleExtra(U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH.name())) != null) {
            u2fTokenIntentType = U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH;
            Parcelable[] allParcelables = data.getParcelableArray("signBatch");
            if (allParcelables != null) {
                authenticationRequests = new AuthenticationRequest[allParcelables.length];
                for (int i = 0; i < allParcelables.length; i++) {
                    authenticationRequests[i] = (AuthenticationRequest)allParcelables[i];
                    LogUtils.d("authenticationRequests: " + authenticationRequests[i]);
                }
            }
            illegal_intent = false;
            TextView tv = (TextView) findViewById(R.id.msg);
            tv.setText("processing...");
        }
        else if ((data = intent.getBundleExtra(U2FTokenIntentType.U2F_OPERATION_REG.name())) != null) {
            LogUtils.d("this is reg");
            u2fTokenIntentType = U2FTokenIntentType.U2F_OPERATION_REG;
            data.setClassLoader(RegistrationRequest.class.getClassLoader());
            registrationRequest = data.getParcelable("registerRequest");
            LogUtils.d(registrationRequest);
//            rawMessage = data.getByteArray("RawMessage");
            Parcelable[] allParcelables = data.getParcelableArray("signBatch");
            if (allParcelables != null) {
                authenticationRequests = new AuthenticationRequest[allParcelables.length];
                for (int i = 0; i < allParcelables.length; i++) {
                    authenticationRequests[i] = (AuthenticationRequest)allParcelables[i];
                }
            } else {
                LogUtils.d("authenticationRequests is null");
            }
            illegal_intent = false;
            TextView tv = (TextView) findViewById(R.id.msg);
            tv.setText("processing...");
        } else {
            TextView tv = (TextView) findViewById(R.id.msg);
            tv.setText("illegal intent");
            illegal_intent = true;
            return;
        }

        TokenMessageRequest request = new TokenMessageRequest(registrationRequest,
                authenticationRequests, u2fTokenIntentType, u2fToken, responseHandler);

//        new Thread(request).start();
        ExecutorService exec = Executors.newSingleThreadExecutor();
        exec.execute(request);
        exec.shutdown();
        requestHandle = new RequestHandle(request);
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (!illegal_intent) {
            synchronized (userPresenceLock) {
                if (CHECKONLY_FINISHED == false) {
                    try {
                        userPresenceLock.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                        throw new RuntimeException(e);
                    }
                }
            }
            if (!USER_PRESENCE) {
                userPresenceVerifier();
            }
        }

    }

    private void userPresenceVerifier() {
        // user presence with bank card
        JSONObject jsonm = new JSONObject();
        try {
            jsonm.put(WepayPlugin.merchantCode, "1000000200");
            jsonm.put(WepayPlugin.outOrderId, getRandomNum(12));
            jsonm.put(WepayPlugin.nonceStr, getRandomNum(32));
            jsonm.put(WepayPlugin.noticeUrl, "http://192.168.6.34:10000/merchant/telcharge_notice.jsp");
            /********MD5签名*********/
            String signmd5Src = MD5Encrypt.signJsonStringSort(jsonm.toString());
            String signmd5 = MD5Encrypt.sign(signmd5Src, "123456ADSEF");
            jsonm.put(WepayPlugin.sign, signmd5);
        } catch (Exception e) {
            e.printStackTrace();
        }
        WepayPlugin.getInstance().genWepayQueryRequestJar(this, jsonm.toString(), true);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == WepayPlugin.reqCod) {
            if (data != null) {
                Bundle mbundle = data.getExtras();
                /**
                 * 支付取消
                 */
                int REAULT_CANCEL_CODE = 24;
                /**
                 * 支付成功
                 */
                int REAULT_SUCCESS_CODE = 25;
                /**
                 * 支付出错
                 */
                int REAULT_ERROR_CODE = 26;
                if (mbundle.getBoolean("isPay")) //支付
                {
                    if (mbundle.getInt("code") == REAULT_SUCCESS_CODE) {
                        Toast.makeText(this, "支付成功", Toast.LENGTH_SHORT).show();
                        Log.i("Nfc-Pay:", mbundle.getString("data"));
                    } else if (mbundle.getInt("code") == REAULT_ERROR_CODE)
                        Toast.makeText(this, "支付失败", Toast.LENGTH_SHORT).show();
                    else if (mbundle.getInt("code") == REAULT_CANCEL_CODE)
                        Toast.makeText(this, "支付已取消", Toast.LENGTH_SHORT).show();
                    else Toast.makeText(this, "数据异常", Toast.LENGTH_SHORT).show();

                } else //余额查询
                {
                    if (mbundle.getInt("code") == REAULT_SUCCESS_CODE) {
                        Toast.makeText(this, " 余额查询成功", Toast.LENGTH_SHORT).show();
                        Log.i("Nfc-Query:", mbundle.getString("data"));
//                        lock.lock();
//                        try {
//                            USER_PRESENCE = true;
//                            condition.signalAll();
//                        } finally {
//                            lock.unlock();
//                        }
                        synchronized (lock) {
                            USER_PRESENCE = true;
                            lock.notify();
                        }


                    } else if (mbundle.getInt("code") == REAULT_ERROR_CODE) {
                        Toast.makeText(this, " 余额查询失败", Toast.LENGTH_SHORT).show();
                        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                        i.putExtra("SW", SW_TEST_OF_PRESENCE_REQUIRED);
                        setResult(RESULT_CANCELED, i);
                        LogUtils.d("余额查询失败");
                        finish();
                    }
                    else if (mbundle.getInt("code") == REAULT_CANCEL_CODE) {
                        Toast.makeText(this, " 余额查询已取消", Toast.LENGTH_SHORT).show();
                        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                        i.putExtra("SW", SW_TEST_OF_PRESENCE_REQUIRED);
                        setResult(RESULT_CANCELED, i);
                        LogUtils.d("余额查询失败");
                        finish();
                    }


                }

            } else {
                Toast.makeText(this, "出错啦", Toast.LENGTH_SHORT).show();
            }
        }else if(requestCode == WepayPlugin.cardNoCod){
            if (data != null) {
                Bundle mbundle = data.getExtras();
                /**
                 * 支付取消
                 */
                int REAULT_CANCEL_CODE = 24;
                /**
                 * 支付成功
                 */
                int REAULT_SUCCESS_CODE = 25;
                /**
                 * 支付出错
                 */
                int REAULT_ERROR_CODE = 26;

                if (mbundle.getInt("code") == REAULT_SUCCESS_CODE) {
                    Toast.makeText(this, "获取卡号成功", Toast.LENGTH_SHORT).show();
                    Log.i("Nfc-CardNo:", mbundle.getString("data"));
                } else if (mbundle.getInt("code") == REAULT_ERROR_CODE) {
                    Toast.makeText(this, "获取卡号失败", Toast.LENGTH_SHORT).show();
                } else if (mbundle.getInt("code") == REAULT_CANCEL_CODE) {
                    Toast.makeText(this, "获取卡号取消", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "数据异常", Toast.LENGTH_SHORT).show();
                }
            } else {
                Toast.makeText(this, "出错啦", Toast.LENGTH_SHORT).show();
            }
        }
    }

    /**
     * 获取随机字符串
     *
     * @param len 长度
     * @return 随机字符串
     */
    public static String getRandomNum(int len) {
        String[] arr = {"0", "1", "2", "3", "4", "5", "6", "7",
                "8", "9"};
        String s = "";
        if (len <= 0) {
            return s;
        }
        Random ra = new Random();
        int arrLen = arr.length;
        for (int i = 0; i < len; i++) {
            s += arr[ra.nextInt(arrLen)];
        }
        return s;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (requestHandle != null && !requestHandle.isCancelled() && !requestHandle.isFinished()) {
            LogUtils.d("Reqeust Handle cancel" + (requestHandle.cancel(true) ? " succeeded" : " failed"));
//            lock.lock();
//            try {
//                USER_PRESENCE = true;
//                condition.signalAll();
//            } finally {
//                lock.unlock();
//            }
            synchronized (lock) {
                USER_PRESENCE = true;
                lock.notify();
            }
        } else {
            LogUtils.d("Request Handle already non-cancellable");
        }
    }

    private static class ResponseHandler implements ResponseHandlerInterface {
        private final WeakReference<U2FTokenActivity> activity;
        public ResponseHandler(U2FTokenActivity activity) {
            this.activity = new WeakReference<U2FTokenActivity>(activity);
        }

        @Override
        public void sendStartMessage() {
            LogUtils.d("sendStartMessage");
        }

        @Override
        public void onCheckOnlyFinish() { // Token has already been registered
            LogUtils.d("onCheckOnlyFinish");
            final U2FTokenActivity _activity = activity.get();
            if (_activity != null) {
                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                i.putExtra("SW", SW_TEST_OF_PRESENCE_REQUIRED);
                _activity.setResult(RESULT_OK, i);
                _activity.finish();
            }
            USER_PRESENCE = true;
            synchronized (userPresenceLock) {
                CHECKONLY_FINISHED = true;
                userPresenceLock.notify();
            }

        }

        @Override
        public void onRegisterFinish(RegistrationResponse response) {
            LogUtils.d("onRegisterFinish");
            final U2FTokenActivity _activity = activity.get();
            if (_activity != null) {
                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                Bundle data = new Bundle();
                data.putByteArray("RawMessage", RawMessageCodec.encodeRegistrationResponse(response));
                i.putExtras(data);
                _activity.setResult(RESULT_OK, i);
                _activity.finish();
                USER_PRESENCE = false;
            }
        }

        @Override
        public void onAuthenticateFinish(AuthenticationResponse response, int index) {
            LogUtils.d("onAuthenticateFinish");
            final U2FTokenActivity _activity = activity.get();
            if (_activity != null) {
                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                Bundle data = new Bundle();
                data.putByteArray("RawMessage", RawMessageCodec.encodeAuthenticationResponse(response));
                data.putInt("keyHandleIndex", index);
                i.putExtras(data);
                _activity.setResult(RESULT_OK, i);
                _activity.finish();
                USER_PRESENCE = false;
                return;
            }
        }

        @Override
        public void onAuthenticateFail() {
            LogUtils.d("onAuthenticateFail");
            final U2FTokenActivity _activity = activity.get();
            if (_activity != null) {
                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                i.putExtra("SW", SW_INVALID_KEY_HANDLE);
                _activity.setResult(RESULT_CANCELED, i);
                _activity.finish();
            }
        }

        @Override
        public void sendCancelMessage() {
            LogUtils.d("sendCancelMessage");
//            final U2FTokenActivity _activity = activity.get();
//            if (_activity != null) {
//                Toast.makeText(_activity, "You cancelled token task.", Toast.LENGTH_LONG).show();
//            }
        }
    }
}
