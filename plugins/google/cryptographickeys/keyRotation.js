var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Key Rotation',
    category: 'Cryptographic Keys',
    description: 'Ensures cryptographic keys are set to rotate on a regular schedule',
    more_info: 'All cryptographic keys should have key rotation enabled. Google will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.',
    link: 'https://cloud.google.com/vpc/docs/using-cryptoKeys',
    recommended_action: 'Ensure that cryptographic keys are set to rotate.',
    apis: ['keyRings:list','cryptoKeys:list'],
    compliance: {
        pci: 'PCI has strict requirements regarding the use of encryption keys ' +
             'to protect cardholder data. These requirements include rotating ' +
             'the key periodically. Cryptographic Keys provides key rotation capabilities that ' +
             'should be enabled.',
        hipaa: 'Rotating keys helps to ensure that those keys have not been ' +
            'compromised. HIPAA requires strict controls around authentication of ' +
            'users or systems accessing HIPAA-compliant environments.',

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
                helpers.addResult(results, 3, 'Unable to query cryptographic keys: ' + helpers.addError(cryptoKeys), region);
                return rcb();
            }

            if (!cryptoKeys.data.length) {
                helpers.addResult(results, 0, 'No cryptographic keys found', region);
                return rcb();
            }

            cryptoKeys.data.forEach(cryptoKey => {
                if (cryptoKey.rotationPeriod) {
                    helpers.addResult(results, 0, 'Key rotation is enabled', region, cryptoKey.name);
                } else {
                    helpers.addResult(results, 2, 'Key rotation is not enabled', region, cryptoKey.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}