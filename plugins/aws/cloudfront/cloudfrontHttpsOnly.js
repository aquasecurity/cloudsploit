var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront HTTPS Only',
    category: 'CloudFront',
    description: 'Ensures CloudFront distributions are configured to redirect non-HTTPS traffic to HTTPS.',
    more_info: 'For maximum security, CloudFront distributions can be configured to only accept HTTPS connections or to redirect HTTP connections to HTTPS.',
    link: 'http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CloudFront.html',
    recommended_action: 'Remove HTTP-only listeners from distributions.',
    apis: ['CloudFront:listDistributions', 'CloudFront:getDistribution'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'CloudFront HTTPS redirection should be used to ensure site visitors ' +
                'are always connecting over a secure channel.'
    },
    remediation_description: 'CloudFront distribution will be configured to only accept HTTPS connections or to redirect HTTP connections to HTTPS.',
    remediation_min_version: '202101041100',
    apis_remediate: ['CloudFront:listDistributions', 'CloudFront:getDistribution'],
    actions: {
        remediate: ['CloudFront:updateDistribution'],
        rollback: ['CloudFront:updateDistribution']
    },
    permissions: {
        remediate: ['cloudfront:UpdateDistribution'],
        rollback: ['cloudfront:UpdateDistribution']
    },
    realtime_triggers: ['cloudfront:CreateDistribution', 'cloudfront:UpdateDistribution'],
    remediation_inputs: {
        cdnPolicyOption: {
            name: 'Viewer Protocol Policy Option',
            description: 'https-only | redirect-to-https',
            regex: '^(https-only|redirect-to-https)$',
            required: false
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listDistributions = helpers.addSource(cache, source,
            ['cloudfront', 'listDistributions', region]);

        if (!listDistributions) return callback(null, results, source);

        if (listDistributions.err || !listDistributions.data) {
            helpers.addResult(results, 3,
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No CloudFront distributions found');
            return callback(null, results, source);
        }
        // loop through Instances for every reservation
        listDistributions.data.forEach(function(Distribution){

            if (Distribution.DefaultCacheBehavior.ViewerProtocolPolicy == 'redirect-to-https') {
                helpers.addResult(results, 0, 'CloudFront distribution ' + 
                    'is configured to redirect non-HTTPS traffic to HTTPS', 'global', Distribution.ARN);
            } else if (Distribution.DefaultCacheBehavior.ViewerProtocolPolicy == 'https-only') {
                helpers.addResult(results, 0, 'The CloudFront ' + 
                    'distribution is set to use HTTPS only.', 'global', Distribution.ARN);
            } else {
                helpers.addResult(results, 2, 'CloudFront distribution ' + 
                    'is not configured to use HTTPS', 'global', Distribution.ARN);
            }
        });

        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'cloudfrontHttpsOnly';
        var distributionNameArr = resource.split(':');
        var distributionName = distributionNameArr[distributionNameArr.length - 1].split('/');
        var cdnId = distributionName[1];
        var distributionLocation = helpers.defaultRegion(settings);

        var getDistribution = helpers.addSource(cache, {},
            ['cloudfront', 'getDistribution', distributionLocation, cdnId]);

        var params = {};

        if (getDistribution &&
            getDistribution.data &&
            getDistribution.data.ETag &&
            getDistribution.data.Distribution &&
            getDistribution.data.Distribution.DistributionConfig) {
            params['DistributionConfig'] = getDistribution.data.Distribution.DistributionConfig;
            
            if (settings.input && settings.input.cdnPolicyOption) params['DistributionConfig']['ViewerProtocolPolicy'] = settings.input.cdnPolicyOption;
            else params['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy'] = 'redirect-to-https';

            params['Id'] = cdnId;
            params['IfMatch'] = getDistribution.data.ETag;
        } else {
            return callback('Unable to get CloudFront distribution', null);
        }

        config.region = distributionLocation;

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'HTTPSOnly': 'Disabled',
            'CloudFront': resource
        };
        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'HTTPSOnly',
                'CloudTrail': cdnId
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};