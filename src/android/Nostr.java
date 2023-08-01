package com.nostr.band.walletStore;

import static com.nostr.band.walletStore.Bech32.Encoding;
import static com.nostr.band.walletStore.Bech32.decodeBytes;
import static com.nostr.band.walletStore.KeyStorage.readValues;
import static com.nostr.band.walletStore.KeyStorage.removeValues;
import static com.nostr.band.walletStore.KeyStorage.writeValues;
import static com.nostr.band.walletStore.Utils.decrypt;
import static com.nostr.band.walletStore.Utils.encrypt;
import static com.nostr.band.walletStore.Utils.generateId;
import static com.nostr.band.walletStore.Utils.pubkeyCreate;
import static com.nostr.band.walletStore.Utils.sign;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.security.KeyPairGeneratorSpec;
import android.util.Log;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.journeyapps.barcodescanner.BarcodeEncoder;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

import kotlin.Triple;


public class Nostr extends CordovaPlugin {

  private static final String WALLETS_ALIAS = "nostrWalletKeys";
  private static final String CURRENT_ALIAS = "currentAlias";
  private static final String KEYSTORE_PROVIDER_1 = "AndroidKeyStore";
  private static final String KEYSTORE_PROVIDER_2 = "AndroidKeyStoreBCWorkaround";
  private static final String KEYSTORE_PROVIDER_3 = "AndroidOpenSSL";
  private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
  private static final String TAG = "NostrWalletLogTag";
  private static final String WALLET_KEY_PREFIX = "nostr+walletconnect:";


  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {

    if (action.equals("addWallet")) {

      return addWallet(callbackContext);

    } else if (action.equals("editWallet")) {

      return editWallet(args, callbackContext);

    } else if (action.equals("deleteWallet")) {

      return deleteWallet(args, callbackContext);

    } else if (action.equals("listWallets")) {

      return listWallets(callbackContext);

    } else if (action.equals("selectWallet")) {

      return selectWallet(args, callbackContext);

    } else if (action.equals("getInfo")) {

      return getInfo(callbackContext);

    } else if (action.equals("signEvent")) {

      return signEvent(args, callbackContext);

    } else if (action.equals("encryptData")) {

      return encryptData(args, callbackContext);

    } else if (action.equals("decryptData")) {

      return decryptData(args, callbackContext);

    } else if (action.equals("showKey")) {

      return showKey(args, callbackContext);

    }

    return false;
  }

  private boolean addWallet(CallbackContext callbackContext) {

    addWalletPrompt(callbackContext);

    return true;
  }

  private boolean editWallet(JSONArray args, CallbackContext callbackContext) throws JSONException {

    JSONObject jsonObject = args.getJSONObject(0);
    String id = jsonObject.getString("id");
    String name = jsonObject.getString("name");

    String keysData = getKeysStringData();
    JSONObject keysObjectData = getKeysObjectData(keysData);

    if (!existWalletKey(id, keysObjectData)) {
      callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Wallet key doesn't exist"));
      return false;
    }
    if (existWalletKeyName(id, name, keysObjectData)) {
      callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Wallet name already exist"));
      return false;
    }

    JSONObject key = keysObjectData.getJSONObject(id);
    key.put("name", name);

    writeValues(getContext(), WALLETS_ALIAS, keysObjectData.toString().getBytes());

    callbackContext.success(keysObjectData);

    return true;
  }

  private boolean deleteWallet(JSONArray args, CallbackContext callbackContext) throws JSONException {

    JSONObject jsonObject = args.getJSONObject(0);
    String id = jsonObject.getString("id");

    String keysData = getKeysStringData();
    JSONObject keysObjectData = getKeysObjectData(keysData);

    if (!existWalletKey(id, keysObjectData)) {
      callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Wallet Key doesn't exist"));
      return false;
    }

    Runnable runnable = () -> {
      AlertDialog.Builder alertDialogBuilder = initAlertDialog("", "Do you want delete wallet?");
      setPositiveDeleteButton(alertDialogBuilder, "ok", keysObjectData, id, callbackContext);
      setNegativeButton(alertDialogBuilder, "cancel", callbackContext, PluginResult.Status.OK);
      setOnCancelListener(alertDialogBuilder, callbackContext, PluginResult.Status.OK);
      AlertDialog alertDialog = showAlertDialog(alertDialogBuilder);
      changeTextDirection(alertDialog);
    };

    this.cordova.getActivity().runOnUiThread(runnable);

    return true;
  }

  private boolean listWallets(CallbackContext callbackContext) throws JSONException {
    String keysData = getKeysStringData();
    JSONObject keysObjectData = getKeysObjectData(keysData);

    callbackContext.success(keysObjectData);

    return true;
  }

  private boolean getInfo(CallbackContext callbackContext) throws JSONException {
    String keysData = getKeysStringData();
    JSONObject keysObjectData = getKeysObjectData(keysData);

    String currentPublicWallet = keysObjectData.getString(CURRENT_ALIAS);

    callbackContext.success(keysObjectData.getJSONObject(currentPublicWallet));

    return true;
  }

  private boolean selectWallet(JSONArray args, CallbackContext callbackContext) throws JSONException {

    JSONObject jsonObject = args.getJSONObject(0);
    String id = jsonObject.getString("id");

    String keysData = getKeysStringData();
    JSONObject keysObjectData = getKeysObjectData(keysData);

    if (!existWalletKey(id, keysObjectData)) {
      callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Key doesn't exist"));
      return false;
    }

    keysObjectData.put(CURRENT_ALIAS, id);

    writeValues(getContext(), WALLETS_ALIAS, keysObjectData.toString().getBytes());

    callbackContext.success(keysObjectData);

    return true;
  }

  private synchronized void addWalletPrompt(CallbackContext callbackContext) {

    Runnable runnable = () -> {
      AlertDialog.Builder alertDialogBuilder = initAlertDialog("Please enter your wallet key", "Wallet key");

      TextInputLayout namePromptInput = initInput("name");
      TextInputLayout nsecPromptInput = initInput(WALLET_KEY_PREFIX + "...");
      initWalletKeyInputs(alertDialogBuilder, namePromptInput, nsecPromptInput);

      setNegativeButton(alertDialogBuilder, "cancel", callbackContext, PluginResult.Status.ERROR);
      setAddWalletPositiveButton(alertDialogBuilder, "save", namePromptInput, nsecPromptInput, callbackContext);
      setOnCancelListener(alertDialogBuilder, callbackContext, PluginResult.Status.ERROR);

      AlertDialog alertDialog = showAlertDialog(alertDialogBuilder);
      changeTextDirection(alertDialog);
    };

    this.cordova.getActivity().runOnUiThread(runnable);
  }

  private boolean signEvent(JSONArray args, CallbackContext callbackContext) throws JSONException {

    String currentAlias = getCurrentAlias();
    String privateKey = getPrivateKey(currentAlias);
    byte[] publicKey = pubkeyCreate(getBytePrivateKey(privateKey));
    JSONObject jsonObject = args.getJSONObject(0);
    int kind = jsonObject.getInt("kind");
    String content = jsonObject.getString("content");
    List<List<String>> tags = parseTags(jsonObject.getJSONArray("tags"));
    long createdAt = jsonObject.getLong("created_at");
    byte[] bytes = generateId(publicKey, createdAt, kind, tags, content);

    byte[] sign = sign(bytes, getBytePrivateKey(privateKey));
    String id = new String(Hex.encode(bytes), StandardCharsets.UTF_8);
    String signString = new String(Hex.encode(sign), StandardCharsets.UTF_8);
    String publicKeyString = new String(generatePublicKey(privateKey), StandardCharsets.UTF_8);

    jsonObject.put("id", id);
    jsonObject.put("pubkey", publicKeyString);
    jsonObject.put("sig", signString);

    callbackContext.success(jsonObject);

    return true;
  }

  private boolean encryptData(JSONArray args, CallbackContext callbackContext) throws JSONException {
    JSONObject jsonObject = args.getJSONObject(0);
    String publicKey = jsonObject.getString("pubkey");
    String plainText = jsonObject.getString("plaintext");

    String currentAlias = getCurrentAlias();
    String privateKey = getPrivateKey(currentAlias);
    byte[] bytePrivateKey = getBytePrivateKey(privateKey);

    String encryptedText = encrypt(plainText, bytePrivateKey, Hex.decode(publicKey));

    callbackContext.success(encryptedText);

    return true;
  }

  private boolean decryptData(JSONArray args, CallbackContext callbackContext) throws JSONException {
    JSONObject jsonObject = args.getJSONObject(0);
    String publicKey = jsonObject.getString("pubkey");
    String cipherText = jsonObject.getString("ciphertext");

    String currentAlias = getCurrentAlias();
    String privateKey = getPrivateKey(currentAlias);
    byte[] bytePrivateKey = getBytePrivateKey(privateKey);

    String encryptedText = decrypt(cipherText, bytePrivateKey, Hex.decode(publicKey));

    callbackContext.success(encryptedText);

    return true;
  }

  private boolean showKey(JSONArray args, CallbackContext callbackContext) throws JSONException {

    JSONObject jsonObject = args.getJSONObject(0);
    String id = jsonObject.getString("id");

    String walletPrivateKey = getPrivateKey(id);

    String keysData = getKeysStringData();
    JSONObject keysObjectData = getKeysObjectData(keysData);
    JSONObject walletData = keysObjectData.getJSONObject(id);
    String walletKey = WALLET_KEY_PREFIX +
            walletData.getString("publicKey") +
            "?relay=" + walletData.getString("relay") +
            "&secret=" + walletPrivateKey;

    if ("".equals(walletPrivateKey)) {
      callbackContext.error("Key doesn't exist");
      return false;
    }

    Runnable runnable = () -> {
      AlertDialog.Builder alertDialogBuilder = initAlertDialog(walletKey, "Wallet Key");
      setQrCodeToAlertDialog(alertDialogBuilder, walletKey);
      setNegativeButton(alertDialogBuilder, "ok", callbackContext, PluginResult.Status.OK);
      setCopyButton(alertDialogBuilder, "Wallet key", walletKey);
      setOnCancelListener(alertDialogBuilder, callbackContext, PluginResult.Status.OK);
      AlertDialog alertDialog = showAlertDialog(alertDialogBuilder);
      changeTextDirection(alertDialog);
    };

    this.cordova.getActivity().runOnUiThread(runnable);

    return true;
  }

  private void setCopyButton(AlertDialog.Builder alertDialog, String label, String copyText) {
    alertDialog.setNeutralButton("Copy",
            (dialog, which) -> {
              ClipboardManager clipboardManager = (ClipboardManager) cordova.getActivity().getSystemService(Context.CLIPBOARD_SERVICE);
              ClipData clipData = ClipData.newPlainText(label, copyText);
              clipboardManager.setPrimaryClip(clipData);
            });
  }

  private void setQrCodeToAlertDialog(AlertDialog.Builder alertDialog, String message) {
    try {
      MultiFormatWriter multiFormatWriter = new MultiFormatWriter();
      BitMatrix bitMatrix = multiFormatWriter.encode(message, BarcodeFormat.QR_CODE, 500, 500);
      BarcodeEncoder barcodeEncoder = new BarcodeEncoder();
      final Bitmap bitmap = barcodeEncoder.createBitmap(bitMatrix);
      ImageView imageView = new ImageView(getContext());
      imageView.setImageBitmap(bitmap);
      alertDialog.setView(imageView);
    } catch (WriterException e) {
      e.printStackTrace();
    }
  }

  private AlertDialog.Builder initAlertDialog(String message, String title) {
    AlertDialog.Builder alertDialog = createDialog(cordova);
    alertDialog.setMessage(message);
    alertDialog.setTitle(title);
    alertDialog.setCancelable(true);

    return alertDialog;
  }

  @SuppressLint("NewApi")
  private AlertDialog.Builder createDialog(CordovaInterface cordova) {
    int currentApiVersion = android.os.Build.VERSION.SDK_INT;
    if (currentApiVersion >= android.os.Build.VERSION_CODES.HONEYCOMB) {
      return new AlertDialog.Builder(cordova.getActivity(), AlertDialog.THEME_DEVICE_DEFAULT_DARK);
    } else {
      return new AlertDialog.Builder(cordova.getActivity());
    }
  }

  @SuppressLint("RestrictedApi")
  private TextInputLayout initInput(String defaultText) {

    TextInputLayout textInputLayout = new TextInputLayout(cordova.getActivity(), null, com.google.android.material.R.style.Widget_MaterialComponents_TextInputLayout_OutlinedBox);
    textInputLayout.setBoxStrokeColor(Color.BLACK);
    textInputLayout.setPadding(50, 0, 50, 0);

    TextInputEditText editText = new TextInputEditText(textInputLayout.getContext());
    editText.setBackgroundColor(Color.WHITE);

    editText.setTextColor(Color.BLACK);
    editText.setText(defaultText);
    editText.setPadding(50, editText.getPaddingTop(), editText.getPaddingRight(), editText.getPaddingBottom());

    textInputLayout.addView(editText);

    return textInputLayout;
  }

  private void initWalletKeyInputs(AlertDialog.Builder alertDialog, TextInputLayout namePromptInput, TextInputLayout nsecPromptInput) {
    LinearLayout linearLayout = new LinearLayout(alertDialog.getContext());
    linearLayout.setOrientation(LinearLayout.VERTICAL);
    linearLayout.addView(namePromptInput);
    linearLayout.addView(nsecPromptInput);

    alertDialog.setView(linearLayout);
  }

  private void setNegativeButton(AlertDialog.Builder alertDialog, String buttonLabel, CallbackContext callbackContext, PluginResult.Status status) {
    alertDialog.setNegativeButton(buttonLabel,
            (dialog, which) -> {
              dialog.dismiss();
              callbackContext.sendPluginResult(new PluginResult(status));
            });
  }

  private void setAddWalletPositiveButton(AlertDialog.Builder alertDialog, String buttonLabel, TextInputLayout namePromptInput, TextInputLayout nsecPromptInput, CallbackContext callbackContext) {
    alertDialog.setPositiveButton(buttonLabel,
            (dialog, which) -> {
              dialog.dismiss();
              String walletKey = nsecPromptInput.getEditText() != null ? nsecPromptInput.getEditText().getText().toString().trim() : "";
              String walletName = namePromptInput.getEditText() != null ? namePromptInput.getEditText().getText().toString().trim() : "";

              if (!isValidAddKeyInputValues(walletKey, walletName)) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, "PrivateKey or Name isn't valid"));
                return;
              }

              String id = new String(generateRandomIntArray(64), StandardCharsets.UTF_8);
              String publicKey = getPublicWalletKeyFromInputWalletKey(walletKey);
              String privateKey = getPrivateWalletKeyFromInputWalletKey(walletKey);
              String relayKey = getWalletRelayFromInputWalletKey(walletKey);

              try {
                String keysData = getKeysStringData();
                JSONObject keysObjectData = getKeysObjectData(keysData);
                if (existWalletKey(publicKey, keysObjectData)) {
                  callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Key already exist"));
                  return;
                }
                if (existWalletKeyName(publicKey, walletName, keysObjectData)) {
                  callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Name already exist"));
                  return;
                }
                saveCurrentAlias(keysObjectData, walletName, publicKey, relayKey, id);

                savePrivateKey(id, privateKey);

                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, keysObjectData.getJSONObject(id)));
              } catch (JSONException e) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Something went wrong"));
              }
            });
  }

  private void setOnCancelListener(AlertDialog.Builder alertDialog, CallbackContext callbackContext, PluginResult.Status status) {
    alertDialog.setOnCancelListener(dialog -> {
      dialog.dismiss();
      callbackContext.sendPluginResult(new PluginResult(status));
    });
  }

  private AlertDialog showAlertDialog(AlertDialog.Builder dlg) {
    return dlg.show();
  }

  @SuppressLint("NewApi")
  private void changeTextDirection(AlertDialog alertDialog) {
    int currentApiVersion = android.os.Build.VERSION.SDK_INT;
    if (currentApiVersion >= android.os.Build.VERSION_CODES.JELLY_BEAN_MR1) {
      TextView messageView = alertDialog.findViewById(android.R.id.message);
      messageView.setTextDirection(android.view.View.TEXT_DIRECTION_LOCALE);
    }
  }

  private boolean isValidAddKeyInputValues(String walletKey, String name) {
    if ((name == null || "".equals(name)) || (walletKey == null || "".equals(walletKey))) {
      return false;
    }

    try {
      //todo add wallet key validation(get requirements)
    } catch (IllegalArgumentException e) {
      return false;
    }

    return true;
  }

  private String getPublicWalletKeyFromInputWalletKey(String walletKey) {
    walletKey = walletKey.replaceFirst(WALLET_KEY_PREFIX, "");
    return walletKey.substring(0, walletKey.indexOf("?"));
  }

  private String getPrivateWalletKeyFromInputWalletKey(String walletKey) {
    return walletKey.substring(walletKey.indexOf("secret="), walletKey.length() - 1);
  }

  private String getWalletRelayFromInputWalletKey(String walletKey) {
    String afterRelay = walletKey.substring(walletKey.indexOf("relay="), walletKey.length() - 1);
    return afterRelay.substring(0, walletKey.indexOf("&"));
  }

  private String getKeysStringData() {
    byte[] keys = readValues(getContext(), WALLETS_ALIAS);
    return new String(keys);
  }

  private Context getContext() {
    return cordova.getActivity().getApplicationContext();
  }

  private JSONObject getKeysObjectData(String stringData) throws JSONException {
    if (stringData != null && !stringData.equals("")) {
      return new JSONObject(stringData);
    }
    return new JSONObject();
  }

  private boolean existWalletKey(String publicKey, JSONObject keysObjectData) throws JSONException {

    Set<String> namesList = mapJSONArrayToSet(keysObjectData.names());

    Set<String> namesSet = namesList.stream()
            .filter(keyName -> !CURRENT_ALIAS.equals(keyName) && !publicKey.equals(keyName))
            .map(keyName -> {
              try {
                JSONObject key = keysObjectData.getJSONObject(keyName);
                return key.getString("publicKey");
              } catch (JSONException e) {
                return null;
              }
            })
            .collect(Collectors.toSet());

    return namesSet.contains(publicKey);
  }

  private boolean existWalletKeyName(String publicKey, String name, JSONObject keysObjectData) throws JSONException {

    Set<String> namesList = mapJSONArrayToSet(keysObjectData.names());

    Set<String> namesSet = namesList.stream()
            .filter(keyName -> !CURRENT_ALIAS.equals(keyName) && !publicKey.equals(keyName))
            .map(keyName -> {
              try {
                JSONObject key = keysObjectData.getJSONObject(keyName);
                return key.getString("name");
              } catch (JSONException e) {
                return null;
              }
            })
            .collect(Collectors.toSet());

    return namesSet.contains(name);
  }

  private Set<String> mapJSONArrayToSet(JSONArray names) throws JSONException {
    Set<String> namesList = new HashSet<>();

    if (names != null && names.length() > 0) {
      for (int i = 0; i < names.length(); i++) {
        String name = names.getString(i);
        namesList.add(name);
      }
    }

    return namesList;
  }

  private void saveCurrentAlias(JSONObject keysObjectData, String keyName, String publicKey, String relay, String id) throws JSONException {
    addKey(keysObjectData, publicKey, keyName, relay, id);
    writeValues(getContext(), WALLETS_ALIAS, keysObjectData.toString().getBytes());
  }

  private void addKey(JSONObject keysObjectData, String publicKey, String keyName, String relay, String id) throws JSONException {
    JSONArray names = keysObjectData.names();
    if (names != null && names.length() > 0) {
      for (int i = 0; i < names.length(); i++) {
        String name = names.getString(i);
        if (!name.equals(CURRENT_ALIAS)) {
          JSONObject jsonObject = keysObjectData.getJSONObject(name);
          jsonObject.put("isCurrent", false);
          keysObjectData.put(name, jsonObject);
        }
      }
    }

    keysObjectData.put(CURRENT_ALIAS, id);

    JSONObject newKey = new JSONObject();
    newKey.put("id", id);
    newKey.put("name", keyName);
    newKey.put("publicKey", publicKey);
    newKey.put("isCurrent", true);
    newKey.put("relay", relay);

    keysObjectData.put(id, newKey);
  }

  private void savePrivateKey(String alias, String input) {

    try {

      KeyStore keyStore = KeyStore.getInstance(getKeyStore());
      keyStore.load(null);

      if (!keyStore.containsAlias(alias)) {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(getContext()).setAlias(alias)
                .setSubject(new X500Principal("CN=" + alias)).setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime()).setEndDate(end.getTime()).build();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", getKeyStore());
        generator.initialize(spec);

        KeyPair keyPair = generator.generateKeyPair();

        Log.i(TAG, "created new key pairs");
      }

      PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

      if (input.isEmpty()) {
        Log.d(TAG, "Exception: input text is empty");
        return;
      }

      Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
      cipherOutputStream.write(input.getBytes(StandardCharsets.UTF_8));
      cipherOutputStream.close();
      byte[] vals = outputStream.toByteArray();

      writeValues(getContext(), alias, vals);
      Log.i(TAG, "key created and stored successfully");

    } catch (Exception e) {
      Log.e(TAG, "Exception: " + e.getMessage());
    }

  }

  private String getKeyStore() {
    try {
      KeyStore.getInstance(KEYSTORE_PROVIDER_1);
      return KEYSTORE_PROVIDER_1;
    } catch (Exception err) {
      try {
        KeyStore.getInstance(KEYSTORE_PROVIDER_2);
        return KEYSTORE_PROVIDER_2;
      } catch (Exception e) {
        return KEYSTORE_PROVIDER_3;
      }
    }
  }

  private JSONObject initResponseJSONObject(String response) {
    final JSONObject result = new JSONObject();
    try {
      result.put("id", response);
    } catch (JSONException e) {
      Log.i("response", response);
      Log.e("JSONException", e.getMessage());
    }

    return result;
  }

  private void setPositiveDeleteButton(AlertDialog.Builder alertDialog, String buttonLabel, JSONObject keysObjectData, String id, CallbackContext callbackContext) {
    alertDialog.setPositiveButton(buttonLabel,
            (dialog, which) -> {
              dialog.dismiss();

              keysObjectData.remove(id);
              try {
                String currentKey = keysObjectData.getString(CURRENT_ALIAS);
                if (currentKey.equals(id)) {
                  keysObjectData.put(CURRENT_ALIAS, "");
                }
              } catch (JSONException e) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, "Something went wrong"));
              }

              removeValues(getContext(), id);

              callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, keysObjectData));
            });
  }

  private String getCurrentAlias() {
    try {
      String keysData = getKeysStringData();
      JSONObject keysObjectData = getKeysObjectData(keysData);
      return keysObjectData.getString(CURRENT_ALIAS);
    } catch (JSONException e) {
      return "";
    }
  }

  private String getPrivateKey(String alias) {
    try {
      KeyStore keyStore = KeyStore.getInstance(getKeyStore());
      keyStore.load(null);
      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

      Cipher output = Cipher.getInstance(RSA_ALGORITHM);
      output.init(Cipher.DECRYPT_MODE, privateKey);
      CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(readValues(getContext(), alias)), output);

      ArrayList<Byte> values = new ArrayList<>();
      int nextByte;
      while ((nextByte = cipherInputStream.read()) != -1) {
        values.add((byte) nextByte);
      }
      byte[] bytes = new byte[values.size()];
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = values.get(i);
      }

      return new String(bytes, 0, bytes.length, StandardCharsets.UTF_8);

    } catch (Exception e) {
      Log.e(TAG, "Exception: " + e.getMessage());
      return "";
    }
  }

  private byte[] getBytePrivateKey(String privateKey) {
    Triple<String, byte[], Encoding> stringEncodingTriple = decodeBytes(privateKey, false);
    return stringEncodingTriple.getSecond();
  }

  private List<List<String>> parseTags(JSONArray jsonArray) throws JSONException {
    List<List<String>> allTags = new ArrayList<>();
    for (int i = 0; i < jsonArray.length(); i++) {
      ArrayList<String> tags = new ArrayList<>();
      JSONArray tagsJsonArray = jsonArray.getJSONArray(i);
      for (int j = 0; j < tagsJsonArray.length(); j++) {
        tags.add(tagsJsonArray.getString(j));
      }
      allTags.add(tags);
    }
    return allTags;
  }

  private byte[] generatePublicKey(String privateKey) {
    byte[] bytes = pubkeyCreate(getBytePrivateKey(privateKey));
    return Hex.encode(bytes);
  }

  private byte[] generateRandomIntArray(int size) {
    SecureRandom random = new SecureRandom();
    byte[] array = new byte[size];
    random.nextBytes(array);
    return array;
  }
}

