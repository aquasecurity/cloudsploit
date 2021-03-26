var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Glue CloudWatch Encrypted Logs',
    category: 'AWS Glue',
    description: 'Ensures that encryption at-rest is enabled when writing AWS Glue logs to Amazon CloudWatch.',
    more_info: 'AWS Glue should have encryption at-rest enabled for AWS Glue logs to ensure security of AWS Glue logs.',
    recommended_action: 'Modify Glue Security Configurations to enable CloudWatch logs encryption at-rest',
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
                    `Unable to query for Glue security configurations: ${helpers.addError(getSecurityConfigurations)}`, region);
                return rcb();
            }

            if (!getSecurityConfigurations.data.length) {
                helpers.addResult(results, 0,
                    'No Glue security configurations found', region);
                return rcb();
            }

            getSecurityConfigurations.data.forEach(configuration => {
                if (!configuration.Name) return;

                var resource = `arn:${awsOrGov}:glue:${region}:${accountId}:/securityConfiguration/${configuration.Name}`;

                if (configuration.EncryptionConfiguration &&
                    configuration.EncryptionConfiguration.CloudWatchEncryption &&
                    configuration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode &&
                    configuration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode === 'SSE-KMS') {
                    helpers.addResult(results, 0,
                        `Glue Security Configuration "${configuration.Name}" has CloudWatch logs encryption enabled`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Glue Security Configuration "${configuration.Name}" has CloudWatch logs encryption disabled`,
                        region, resource);
                }

            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};