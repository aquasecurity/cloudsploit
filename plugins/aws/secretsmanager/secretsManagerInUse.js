var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Secrets Manager Secret Rotation Enabled',
    category: 'Secrets Manager',
    domain: 'Identity and Access Management',
    description: 'Ensure that Amazon Secrets Manager service is being used in your account to manage all the credentials.',
    more_info: 'Amazon Secrets Manager helps you protect sensitive information needed to access your cloud applications, services and resources. Users and apps can use secrets manager to get the secrets stored with a call to Secrets Manager API, enhancing access security.',
    recommended_action: 'Enable Secrets Manager service in your AWS account.',
    apis: ['SecretsManager:listSecrets'],
    link: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/asm_access.html',

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.secretsmanager, (region, rcb) => {
            var listSecrets = helpers.addSource(cache, source, ['secretsmanager', 'listSecrets', region]);

            if (!listSecrets) return rcb();

            if (!listSecrets.data || listSecrets.err) {
                helpers.addResult(results, 3, `Unable to query for Secrets Manager secrets: ${helpers.addError(listSecrets)}`, region);
                return rcb();
            }

            if (!listSecrets.data.length) {
                helpers.addResult(results, 2, `Secrets Manager is not enabled for this region: ${helpers.addError(listSecrets)}`, region);
                return rcb();
            }

            for (let secret of listSecrets.data) {
                if (!secret.ARN) return rcb();

                var resource = secret.ARN;
                helpers.addResult(results, 0, 'Secrets Manager is enabled for this region', region, resource);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
