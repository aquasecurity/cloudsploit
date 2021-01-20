var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Glue Job Bookmark Encryption Enabled',
    category: 'Glue',
    description: 'Ensures that AWS Glue job bookmark encryption is enabled.',
    more_info: 'AWS Glue security configuration should have job bookmark encryption enabled in order to encrypt the bookmark data before it is sent to Amazon S3.',
    recommended_action: 'Recreate Glue security configurations and enable job bookmark encryption',
    link: 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html',
    apis: ['Glue:getSecurityConfigurations', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.glue, function(region, rcb){
            var getSecurityConfigurations = helpers.addSource(cache, source,
                ['glue', 'getSecurityConfigurations', region]);

            if (!getSecurityConfigurations) return rcb();

            if (getSecurityConfigurations.err || !getSecurityConfigurations.data) {
                helpers.addResult(results, 3,
                    `Unable to query Glue security configurations: ${helpers.addError(getSecurityConfigurations)}`, region);
                return rcb();
            }

            if (!getSecurityConfigurations.data.length) {
                helpers.addResult(results, 0,
                    'No AWS Glue security configurations found', region);
                return rcb();
            }

            for (var configuration of getSecurityConfigurations.data) {
                if (!configuration.Name) continue;

                var resource = `arn:${awsOrGov}:glue:${region}:${accountId}:/securityConfiguration/${configuration.Name}`;

                if (configuration && configuration.EncryptionConfiguration &&
                    configuration.EncryptionConfiguration.JobBookmarksEncryption &&
                    configuration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode &&
                    configuration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode.toUpperCase() !== 'DISABLED') {

                    helpers.addResult(results, 0,
                        `Glue Security Configuration "${configuration.Name}" has job bookmark encryption enabled`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Glue Security Configuration "${configuration.Name}" does not have job bookmark encryption enabled`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
