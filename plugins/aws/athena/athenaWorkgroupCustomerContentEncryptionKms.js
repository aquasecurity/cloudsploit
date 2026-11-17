var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Athena Workgroup Customer Content Encryption KMS',
    category: 'Athena',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that Athena workgroups encrypt customer content with a KMS key of the account.',
    more_info: 'The customer content encryption configuration of a workgroup defines the customer managed KMS key that Athena uses to encrypt the data of the user stored by Athena. ' +
        'Without it, that data is encrypted with a key that is not under control of the account. The default primary workgroup is not evaluated.',
    link: 'https://docs.aws.amazon.com/athena/latest/ug/encryption.html',
    recommended_action: 'Modify the Athena workgroup to set the customer content encryption configuration to a KMS key of the account.',
    apis: ['Athena:listWorkGroups', 'Athena:getWorkGroup', 'KMS:listKeys', 'STS:getCallerIdentity'],
    realtime_triggers: ['athena:CreateWorkGroup', 'athena:UpdateWorkGroup', 'athena:DeleteWorkGroup'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.athena, function(region, rcb) {
            var listWorkGroups = helpers.addSource(cache, source, ['athena', 'listWorkGroups', region]);

            if (!listWorkGroups) return rcb();

            if (listWorkGroups.err || !listWorkGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to list Athena workgroups: ' + helpers.addError(listWorkGroups), region);
                return rcb();
            }

            if (!listWorkGroups.data.length) {
                helpers.addResult(results, 0, 'No Athena workgroups found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            var keyArns = listKeys.data.map(function(key) { return key.KeyArn; });

            listWorkGroups.data.forEach(function(workGroup) {
                // arn:aws:athena:region:account-id:workgroup/workgroup-name
                var arn = 'arn:' + awsOrGov + ':athena:' + region + ':' + accountId + ':workgroup/' + workGroup.Name;

                if (workGroup.Name === 'primary') {
                    helpers.addResult(results, 0, 'The default Athena workgroup is not evaluated', region, arn);
                    return;
                }

                var getWorkGroup = helpers.addSource(cache, source, ['athena', 'getWorkGroup', region, workGroup.Name]);

                if (!getWorkGroup || getWorkGroup.err || !getWorkGroup.data || !getWorkGroup.data.WorkGroup) {
                    helpers.addResult(results, 3,
                        'Unable to describe Athena workgroup: ' + helpers.addError(getWorkGroup), region, arn);
                    return;
                }

                var configuration = getWorkGroup.data.WorkGroup.Configuration || {};
                var kmsKey = (configuration.CustomerContentEncryptionConfiguration || {}).KmsKey;

                if (kmsKey && keyArns.indexOf(kmsKey) > -1) {
                    helpers.addResult(results, 0,
                        'Athena workgroup customer content is encrypted with a KMS key of the account', region, arn);
                } else {
                    helpers.addResult(results, 2,
                        'Athena workgroup customer content is not encrypted with a KMS key of the account', region, arn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
