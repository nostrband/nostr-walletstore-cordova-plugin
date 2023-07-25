var exec = require('cordova/exec');

const SERVICE_NAME = "NostrWalletStore";
const ADD_WALLET = "addWallet";

var NostrWalletStore = {

    addWallet: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, ADD_WALLET, [msg]);
    },

};

module.exports = NostrWalletStore;
