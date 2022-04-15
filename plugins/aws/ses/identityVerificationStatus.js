var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SES Identity Verification Status',
    category: 'SES',
    domain: 'Content Delivery',
    description: 'Ensure Amazon Simple Email Service (SES) identities are verified in order to prove their ownership and some safety purposes.',
    more_info: 'The verification status of an email address is "Pending" until the email address owner clicks the link within the verification email that Amazon SES sent to that address. If the email address owner clicks the link within 24 hours, the verification status of the email address changes to "Success". If the link is not clicked within 24 hours, the verification status changes to "Failed." In that case, to verify the email address, you must restart the verification process from the beginning.',
    recommended_action: 'Enable Verification for all addresses in all regions used to send email through SES.',
    link: 'https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html',
    apis: ['SES:listIdentities', 'SES:getIdentityVerificationAttributes', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        console.log(JSON.stringify(cache.ses, null, 2));
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        
        async.each(regions.ses, function(region, rcb){
            var listIdentities = helpers.addSource(cache, source,
                ['ses', 'listIdentities', region]);

            if (!listIdentities) return rcb();

            if (listIdentities.err || !listIdentities.data) {
                helpers.addResult(results, 3,
                    'Unable to list SES identities: ' + helpers.addError(listIdentities), region);
                return rcb();
            }

            if (!listIdentities.data.length) {
                helpers.addResult(results, 0, 'No SES identities found', region);
                return rcb();
            }

            var getIdentityVerificationAttributes = helpers.addSource(cache, source,
                ['ses', 'getIdentityVerificationAttributes', region]);

            if (!getIdentityVerificationAttributes ||
                getIdentityVerificationAttributes.err ||
                !getIdentityVerificationAttributes.data) {
                helpers.addResult(results, 3,
                    'Unable to get SES Verification attributes: ' + helpers.addError(getIdentityVerificationAttributes), region);
                return rcb();
            }
           
            for (var i in getIdentityVerificationAttributes.data.VerificationAttributes) {
                var found = getIdentityVerificationAttributes.data.VerificationAttributes[i];
                let resource = `arn:${awsOrGov}:ses:${region}:${accountId}:identity/${i}`;

                if (found.VerificationStatus === 'Success') {
                    helpers.addResult(results, 0, 'Verification status is a success', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Verification status is not a success', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};