var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'XRay Encryption Enabled',
    category: 'XRay',
    description: 'Ensures CMK-based encryption is enabled for XRay traces.',
    more_info: 'AWS XRay supports default encryption based on an AWS-managed KMS key as well as encryption using a customer managed key (CMK). For maximum security, the CMK-based encryption should be used.',
    link: 'https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html',
    recommended_action: 'Update XRay encryption configuration to use a CMK.',
    apis: ['XRay:getEncryptionConfig'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.xray, function(region, rcb){
            var getEncryptionConfig = helpers.addSource(cache, source,
                ['xray', 'getEncryptionConfig', region]);

            if (!getEncryptionConfig) return rcb();

            if (getEncryptionConfig.err || !getEncryptionConfig.data) {
                helpers.addResult(results, 3,
                    'Unable to query for XRay encryption configuration: ' + helpers.addError(getEncryptionConfig), region);
                return rcb();
            }

            if (getEncryptionConfig.data &&
                getEncryptionConfig.data.Type &&
                getEncryptionConfig.data.Type == 'KMS') {
                if (getEncryptionConfig.data.KeyId) {
                    helpers.addResult(results, 0, 'XRay is configured to use KMS encryption with a CMK', region);
                } else {
                    helpers.addResult(results, 2, 'XRay is configured to use KMS encryption but is not using a CMK', region);
                }
            } else {
                helpers.addResult(results, 2, 'XRay is configured to use default encryption without CMK', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
