var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Encrypted Parameters',
    category: 'SSM',
    description: 'Ensures SSM Parameters are encrypted',
    more_info: 'SSM Parameters should be encrypted. This allows their values to be used by approved systems, while restricting access to other users of the account.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring',
    recommended_action: 'Recreate unencrypted SSM Parameters with Type set to SecureString.',
    apis: ['SSM:describeParameters', 'STS:getCallerIdentity'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest',
        pci: 'PCI requires proper encryption of cardholder data at rest. SSM ' +
             'encryption should be enabled for all parameters storing this type ' +
             'of data.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ssm, function(region, rcb){
            var describeParameters = helpers.addSource(cache, source,
                ['ssm', 'describeParameters', region]);

            if (!describeParameters) return rcb();

            if (describeParameters.err || !describeParameters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Parameters: ' + helpers.addError(describeParameters), region);
                return rcb();
            }

            if (!describeParameters.data.length) {
                helpers.addResult(results, 0, 'No Parameters present', region);
                return rcb();
            }

            for (var i in describeParameters.data) {
                var param = describeParameters.data[i];
                var arn = 'arn:aws:ssm:' + region + ':' + accountId + ':parameter/' + param.Name;

                if (param.Type != 'SecureString') {
                    helpers.addResult(results, 2, 'Non-SecureString Parameters present', region, arn);
                } else {
                    helpers.addResult(results, 0, 'Parameter of Type SecureString', region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
