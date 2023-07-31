var exec = require('cordova/exec');

const SERVICE_NAME = "NostrWalletStore";
const ADD_WALLET = "addWallet";
const EDIT_WALLET = "editWallet";
const DELETE_WALLET = "deleteWallet";
const LIST_WALLETS = "listWallets";
const SELECT_WALLET = "selectWallet";
const GET_INFO = "getInfo";
const SIGN_EVENT = "signEvent";
const ENCRYPT_DATA = "encryptData";
const DECRYPT_DATA = "decryptData";

var NostrWalletStore = {

    addWallet: function (success, error) {
        exec(success, error, SERVICE_NAME, ADD_WALLET, []);
    },
    editWallet: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, EDIT_WALLET, [msg]);
    },
    deleteWallet: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, DELETE_WALLET, [msg]);
    },
    listWallets: function (success, error) {
        exec(success, error, SERVICE_NAME, LIST_WALLETS, []);
    },
    selectWallet: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, SELECT_WALLET, [msg]);
    },
    getInfo: function (success, error) {
        exec(success, error, SERVICE_NAME, GET_INFO, []);
    },
    signEvent: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, SIGN_EVENT, [msg]);
    },
    encryptData: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, ENCRYPT_DATA, [msg]);
    },
    decryptData: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, DECRYPT_DATA, [msg]);
    }
};

module.exports = NostrWalletStore;
