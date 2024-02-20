// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Insecure EC2 Metadata Options',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures EC2 instance metadata is updated to require HttpTokens or disable HttpEndpoint',
    more_info: 'The new EC2 metadata service prevents SSRF attack escalations from accessing the sensitive instance metadata endpoints.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#configuring-instance-metadata-service',
    recommended_action: 'Update instance metadata options to use IMDSv2',
    apis: ['EC2:describeInstances'],
    realtime_triggers: ['ec2:RunInstances', 'ec2:ModifyInstanceMetadataOptions', 'ec2:TerminateInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(
                cache, source, ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3, `Unable to query for instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            var instancesEndpointDisabled = [];
            var instancesTokensRequired = [];
            var instancesInsecure = [];

            for (var reservation of describeInstances.data) {
                var accountId = reservation.OwnerId;
                for (var instance of reservation.Instances) {
                    var arn = `arn:${awsOrGov}:ec2:` + region + ':' + accountId + ':instance/' + instance.InstanceId;

                    if (!instance.MetadataOptions) {
                        helpers.addResult(results, 3, 'Unable to get instance metadata options', region, arn);
                        continue;
                    }

                    if (instance.MetadataOptions.HttpTokens &&
                        instance.MetadataOptions.HttpTokens === 'required') {
                        instancesTokensRequired.push(arn);
                    } else if (instance.MetadataOptions.HttpEndpoint &&
                        instance.MetadataOptions.HttpEndpoint === 'disabled') {
                        instancesEndpointDisabled.push(arn);
                    } else {
                        instancesInsecure.push(arn);
                    }
                }
            }

            var totalCount = instancesInsecure.length + instancesTokensRequired.length + instancesEndpointDisabled.length;

            if (!totalCount) {
                helpers.addResult(results, 0, 'No instances found', region);
            } else {
                // Add individual results
                for (var iArn of instancesEndpointDisabled) {
                    helpers.addResult(results, 0, 'Instance has instance metadata endpoint disabled', region, iArn);
                }

                for (var jArn of instancesTokensRequired) {
                    helpers.addResult(results, 0, 'Instance requires tokens for instance metadata endpoint access', region, jArn);
                }

                for (var kArn of instancesInsecure) {
                    helpers.addResult(results, 2, 'Instance has instance metadata endpoint enabled and does not require HttpTokens', region, kArn);
                }
            }

            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
