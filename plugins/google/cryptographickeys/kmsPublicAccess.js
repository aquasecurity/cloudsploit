var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'KMS Public Access',
    category: 'Cryptographic Keys',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensures cryptographic keys are not publicly accessible.',
    more_info: 'To prevent exposing sensitive data and information leaks, make sure that your cryptokeys do not allow access from anonymous and public users.',
    link: 'https://cloud.google.com/kms/docs/reference/permissions-and-roles',
    recommended_action: 'Ensure that your cryptographic keys are not accessible by allUsers or allAuthenticatedUsers.',
    apis: ['keyRings:list', 'cryptoKeys:list', 'cryptoKeys:getIamPolicy'],
    realtime_triggers: ['CreateKeyRing', 'CreateCryptoKey'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.keyRings, function(region, rcb) {
            let keyRings = helpers.addSource(
                cache, source, ['keyRings', 'list', region]);

            if (!keyRings) return rcb();

            if (keyRings.err || !keyRings.data) {
                helpers.addResult(results, 3, 'Unable to query key rings', region, null, null, keyRings.err);
                return rcb();
            }

            if (!keyRings.data.length) {
                helpers.addResult(results, 0, 'No key rings found', region);
                return rcb();
            }

            let cryptoKeys = helpers.addSource(
                cache, source, ['cryptoKeys', 'list', region]);

            if (!cryptoKeys) return rcb();

            if (cryptoKeys.err || !cryptoKeys.data) {
                helpers.addResult(results, 3, 'Unable to query cryptographic keys', region, null, null, cryptoKeys.err);
                return rcb();
            }

            if (!cryptoKeys.data.length) {
                helpers.addResult(results, 0, 'No cryptographic keys found', region);
                return rcb();
            }

            let cryptoKeysIamPolicies = helpers.addSource(
                cache, source, ['cryptoKeys', 'getIamPolicy', region]);

            if (!cryptoKeysIamPolicies || cryptoKeysIamPolicies.err || !cryptoKeysIamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query IAM Policies for Cryptographic Keys: ' + helpers.addError(cryptoKeysIamPolicies), region);
                return rcb();
            }

            if (!cryptoKeysIamPolicies.data.length) {
                helpers.addResult(results, 0, 'No IAM Policies found', region);
                return rcb();
            }

            cryptoKeysIamPolicies = cryptoKeysIamPolicies.data;

            cryptoKeys.data.forEach(cryptoKey => {     
                if (!cryptoKey.name) return;

                let keyIamPolicy = cryptoKeysIamPolicies.find(iamPolicy => iamPolicy.parent && iamPolicy.parent.name === cryptoKey.name);

                if (!keyIamPolicy || !keyIamPolicy.bindings || !keyIamPolicy.bindings.length) {
                    helpers.addResult(results, 0,
                        'No IAM Policies found for cryptographic key', region, cryptoKey.name);
                } else {
                    var allowedAllUsers = false;
                    keyIamPolicy.bindings.forEach(roleBinding => {
                        if (roleBinding.role && roleBinding.members && roleBinding.members.length && (roleBinding.members.includes('allUsers') || roleBinding.members.includes('allAuthenticatedUsers'))) {
                            allowedAllUsers = true;
                        }
                    });
                    if (!allowedAllUsers) {
                        helpers.addResult(results, 0, 'Cryptographic Key is not publicly accessible', region, cryptoKey.name);
                    } else {
                        helpers.addResult(results, 2, 'Cryptographic Key is publicly accessible', region, cryptoKey.name);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};