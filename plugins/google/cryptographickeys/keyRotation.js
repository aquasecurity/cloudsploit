var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Key Rotation',
    category: 'Cryptographic Keys',
    description: 'Ensures Cryptographic keys are set to rotate on a regular schedule',
    more_info: 'All Cryptographic keys should have key rotation enabled. Google will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.',
    link: 'https://cloud.google.com/vpc/docs/using-cryptoKeys',
    recommended_action: 'Restrict TCP port 5900 to known IP addresses',
    apis: ['keyRings:list','cryptoKeys:list'],
    compliance: {
        pci: 'PCI has strict requirements regarding the use of encryption keys ' +
             'to protect cardholder data. These requirements include rotating ' +
             'the key periodically. Cryptographic Keys provides key rotation capabilities that ' +
             'should be enabled.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.cryptoKeys, function(region, rcb){
            let cryptoKeys = helpers.addSource(
                cache, source, ['cryptoKeys', 'list', region]);

            if (!cryptoKeys) return rcb();

            if (cryptoKeys.err || !cryptoKeys.data) {
                helpers.addResult(results, 3, 'Unable to query Cryptographic Keys: ' + helpers.addError(cryptoKeys), region);
                return rcb();
            }

            if (!cryptoKeys.data.length) {
                helpers.addResult(results, 0, 'No Cryptographic Keys present', region);
                return rcb();
            }

            cryptoKeys.data.forEach(cryptoKey => {
                if (cryptoKey.rotationPeriod) {
                    helpers.addResult(results, 0, 'Key rotation is enabled', region, cryptoKey.name);
                } else {
                    helpers.addResult(results, 2, 'Key rotation is not enabled', region, cryptoKey.name);
                }
            })

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}