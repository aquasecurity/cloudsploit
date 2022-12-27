var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Secret Has Tags',
    category: 'Secrets Manager',
    domain: 'Identity and Access Management',
    description: 'Ensure that AWS Secrets Manager secrets have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Update Secrets and add tags.',
    apis: ['SecretsManager:listSecrets'],
    link: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets_tagging.html',

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
                helpers.addResult(results, 0, 'No secrets found', region);
                return rcb();
            }
            
            for (let secret of listSecrets.data){
                if (!secret.ARN) continue;
                
                if (!secret.Tags || !secret.Tags.length){
                    helpers.addResult(results, 2, 'Secrets Manager secret does not have tags', region, secret.ARN);
                } else {
                    helpers.addResult(results, 0, 'Secrets Manager secret has tags', region, secret.ARN);
                } 
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
