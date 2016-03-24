package org.esec.mcg.androidu2fsimulator.token;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.Toast;

import com.wepayplugin.nfcstd.WepayPlugin;

import org.esec.mcg.androidu2fsimulator.token.impl.LocalU2FToken;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.AuthenticationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.RawMessageCodec;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationRequest;
import org.esec.mcg.androidu2fsimulator.token.msg.RegistrationResponse;
import org.esec.mcg.androidu2fsimulator.token.msg.U2FTokenIntentType;
import org.esec.mcg.androidu2fsimulator.token.utils.logger.LogUtils;
import org.json.JSONObject;

import java.util.Random;

public class U2FTokenActivity extends AppCompatActivity {

    public static final String TEST_OF_PRESENCE_REQUIRED = "error:test-of-user-presence-required";
    public static final String INVALID_KEY_HANDLE = "error:bad-key-handle";
    public static final int SW_TEST_OF_PRESENCE_REQUIRED = 0x6985;
    public static final int SW_INVALID_KEY_HANDLE = 0x6a80;

    private String u2fTokenIntentType;
    private byte[] rawMessage;
    private AuthenticationRequest[] signBatch;
    private int signBatchIndex;

    private U2FToken u2fToken;
    private static boolean USER_PRESENCE = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (getIntent().getBundleExtra(U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH.name()) != null) {
            u2fTokenIntentType = U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH.name();
            Bundle extras = getIntent().getBundleExtra(U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH.name());
            Parcelable[] allParcelables = extras.getParcelableArray("signBatch");
            if (allParcelables != null) {
                LogUtils.d(allParcelables.length);
                LogUtils.d("===================");
                signBatch = new AuthenticationRequest[allParcelables.length];
                for (int i = 0; i < allParcelables.length; i++) {
                    signBatch[i] = (AuthenticationRequest)allParcelables[i];
                }
                LogUtils.d(signBatch[0].getApplicationSha256());
            }
            rawMessage = getIntent().getBundleExtra(U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH.name()).getByteArray("RawMessage");
        }
        else if (getIntent().getBundleExtra(U2FTokenIntentType.U2F_OPERATION_REG.name()) != null) {
            u2fTokenIntentType = U2FTokenIntentType.U2F_OPERATION_REG.name();
            rawMessage = getIntent().getBundleExtra(U2FTokenIntentType.U2F_OPERATION_REG.name()).getByteArray("RawMessage");
        }
        else if (getIntent().getBundleExtra(U2FTokenIntentType.U2F_OPERATION_SIGN.name()) != null) {
            u2fTokenIntentType = U2FTokenIntentType.U2F_OPERATION_SIGN.name();
            Bundle extras = getIntent().getBundleExtra(U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH.name());
            Parcelable[] allParcelables = extras.getParcelableArray("signBatch");
            if (allParcelables != null) {
                LogUtils.d(allParcelables.length);
                LogUtils.d("===================");
                signBatch = new AuthenticationRequest[allParcelables.length];
                for (int i = 0; i < allParcelables.length; i++) {
                    signBatch[i] = (AuthenticationRequest)allParcelables[i];
                }
                LogUtils.d(signBatch[0].getApplicationSha256());
            }
        }
        else {
            throw new RuntimeException("Illegal intent");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();


        if (USER_PRESENCE) {
            localProceed();
            return;
        }
        userPresenceVerifier();
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

    /**
     * Token simulator
     */
    public void localProceed() {
        u2fToken = new LocalU2FToken(this);
        if (U2FTokenIntentType.U2F_OPERATION_REG.name().equals(u2fTokenIntentType)) { // register
            try {
                RegistrationRequest registrationRequest = RawMessageCodec.decodeRegistrationRequest(rawMessage);
                RegistrationResponse registrationResponse = u2fToken.register(registrationRequest);
                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                Bundle data = new Bundle();
                data.putByteArray("RawMessage", RawMessageCodec.encodeRegistrationResponse(registrationResponse));
                i.putExtras(data);
                setResult(RESULT_OK, i);
                finish();
                USER_PRESENCE = false;
            } catch (U2FTokenException e) {
                // TODO: 2016/3/10 How to handle the exception?
                throw new RuntimeException("this should not happen.");
            }
        } else if (U2FTokenIntentType.U2F_OPERATION_SIGN.name().equals(u2fTokenIntentType)) { // sign
            try {
                AuthenticationRequest authenticationRequest = RawMessageCodec.decodeAuthenticationRequest(rawMessage);
                AuthenticationResponse authenticationResponse = u2fToken.authenticate(authenticationRequest);

                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                Bundle data = new Bundle();
                data.putByteArray("RawMessage", RawMessageCodec.encodeAuthenticationResponse(authenticationResponse));
                i.putExtras(data);
                setResult(RESULT_OK, i);
                finish();
                USER_PRESENCE = false;
            } catch (U2FTokenException e) {
                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                if (e.getMessage().equals(TEST_OF_PRESENCE_REQUIRED)) {
                    i.putExtra("SW", SW_TEST_OF_PRESENCE_REQUIRED);
                    setResult(RESULT_CANCELED, i);
                } else if (e.getMessage().equals(INVALID_KEY_HANDLE)) {
                    i.putExtra("SW", SW_INVALID_KEY_HANDLE);
                    setResult(RESULT_CANCELED, i);
                } else {
                    setResult(RESULT_CANCELED);
                }
                finish();
                e.printStackTrace();
            }
        } else if (U2FTokenIntentType.U2F_OPERATION_SIGN_BATCH.name().equals(u2fTokenIntentType)) { // check only
            try {
                LogUtils.d("check only");
                LogUtils.d("signBatchIndex = " + signBatchIndex + "\t length = " + signBatch.length);
                for (;signBatchIndex < signBatch.length; ) {
                    LogUtils.d("for cycle");
                    AuthenticationResponse authenticationResponse = u2fToken.authenticate(signBatch[signBatchIndex]);
                    LogUtils.d("signBatchIndex = " + signBatchIndex + "\t length = " + signBatch.length);

                    Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                    Bundle data = new Bundle();
                    data.putByteArray("RawMessage", RawMessageCodec.encodeAuthenticationResponse(authenticationResponse));
                    i.putExtras(data);
                    setResult(RESULT_OK, i);
                    finish();
                    USER_PRESENCE = false;
                    return;
                }
                if (rawMessage == null) {
                    Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                    i.putExtra("SW", SW_INVALID_KEY_HANDLE);
                    setResult(RESULT_CANCELED, i);
                    LogUtils.d(SW_INVALID_KEY_HANDLE);
                    finish();
                    return;
                }
                u2fTokenIntentType = U2FTokenIntentType.U2F_OPERATION_REG.name();
                localProceed();
            } catch (U2FTokenException e) {
                Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                if (e.getMessage().equals(TEST_OF_PRESENCE_REQUIRED)) {
                    i.putExtra("SW", SW_TEST_OF_PRESENCE_REQUIRED);
                    setResult(RESULT_CANCELED, i);
                    LogUtils.d(TEST_OF_PRESENCE_REQUIRED);
                    finish();
                } else if (e.getMessage().equals(INVALID_KEY_HANDLE)) {
                    signBatchIndex++;
                    localProceed();
                } else {
                    e.printStackTrace();
                    setResult(RESULT_CANCELED);
                    finish();
                }
            }
        } else {
            throw new RuntimeException("never happen!!");
        }
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
                        USER_PRESENCE = true;

                    } else if (mbundle.getInt("code") == REAULT_ERROR_CODE) {
                        Toast.makeText(this, " 余额查询失败", Toast.LENGTH_SHORT).show();
                        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                        i.putExtra("SW", SW_TEST_OF_PRESENCE_REQUIRED);
                        setResult(RESULT_CANCELED, i);
                        USER_PRESENCE = false;
                        finish();
                    }
                    else if (mbundle.getInt("code") == REAULT_CANCEL_CODE) {
                        Toast.makeText(this, " 余额查询已取消", Toast.LENGTH_SHORT).show();
                        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
                        i.putExtra("SW", SW_TEST_OF_PRESENCE_REQUIRED);
                        setResult(RESULT_CANCELED, i);
                        USER_PRESENCE = false;
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

//        if (USER_PRESENCE) {
//            localProceed();
//        }
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
}
