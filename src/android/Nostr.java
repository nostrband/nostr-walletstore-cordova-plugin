package com.nostr.band.walletStore;

import static androidx.core.content.ContextCompat.getSystemService;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;


public class Nostr extends CordovaPlugin {

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {

    if (action.equals("addWallet")) {

      System.out.println("addWallet call");

      return true;

    }

    return false;
  }

}

