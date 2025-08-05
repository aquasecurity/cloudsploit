var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Email DKIM Enabled',
    category: 'SES',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensures DomainKeys Identified Mail (DKIM) is enabled for domains and addresses in SES.',
    more_info: 'DKIM is a security feature that allows recipients of an email to veriy that the sender domain has authorized the message and that it has not been spoofed.',
    recommended_action: 'Enable DKIM for all domains and addresses in all regions used to send email through SES.',
    link: 'http://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html',
    apis: ['SES:listIdentities', 'SES:getIdentityDkimAttributes', 'STS:getCallerIdentity'],
    realtime_triggers: ['ses:CreateEmailIdentity','ses:SetIdentityDkimEnabled', 'ses:PutEmailIdentityDkimAttributes', 'ses:DeleteEmailIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.ses, function(region, rcb){
            var listIdentities = helpers.addSource(cache, source,
                ['ses', 'listIdentities', region]);

            if (!listIdentities) return rcb();

            if (listIdentities.err || !listIdentities.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SES identities: ' + helpers.addError(listIdentities), region);
                return rcb();
            }

            if (!listIdentities.data.length) {
                helpers.addResult(results, 0, 'No SES identities found', region);
                return rcb();
            }

            var getIdentityDkimAttributes = helpers.addSource(cache, source,
                ['ses', 'getIdentityDkimAttributes', region]);

            if (!getIdentityDkimAttributes ||
                getIdentityDkimAttributes.err ||
                !getIdentityDkimAttributes.data) {
                helpers.addResult(results, 3,
                    'Unable to get SES DKIM attributes: ' + helpers.addError(getIdentityDkimAttributes), region);
                return rcb();
            }

            for (var identity of getIdentityDkimAttributes.data.DkimAttributes) {
                if (!identity.identityName) continue;
                var resource = `arn:${awsOrGov}:ses:${region}:${accountId}:identity/${identity.identityName}`;

                if (!identity.DkimEnabled) {
                    helpers.addResult(results, 2, 'DKIM is not enabled', region, resource);
                } else if (identity.DkimVerificationStatus !== 'Success') {
                    helpers.addResult(results, 1,
                        'DKIM is enabled, but not configured properly', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'DKIM is enabled and configured properly', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};