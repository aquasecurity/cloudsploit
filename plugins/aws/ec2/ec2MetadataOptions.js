// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Detect Insecure EC2 Metadata Options',
    category: 'EC2',
    description: 'Ensures EC2 instance metadata is updated to require HttpTokens or disable HttpEndpoint',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#configuring-instance-metadata-service',
    recommended_action: 'Update instance metadata options to use IMDSv2',
    apis: ['EC2:describeInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(cache, source, ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3, `Unable to query for instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            }

            for (reservation of describeInstances.data) {
                for (instance of reservation.Instances) {
                    // When the instance is shutting down or stopped, it no longer maintains
                    // the NetworkInterfaces property used to determine instance VPC placement
                    if (!instance.MetadataOptions) {
                        helpers.addResult(results, 3, `Unable to get instance metadata options`, region, instance.InstanceId);
                        continue;
                    }

                    if (instance.MetadataOptions.HTTPTokens === 'required' || instance.MetadataOptions.HttpEndpoint === 'disabled') {
                        helpers.addResult(results, 0, `Instance metadata options require HttpTokens or disable HttpEndpoint entirely`, region, instance.InstanceId);
                        continue;
                    }
                    helpers.addResult(results, 0, `Insecure instance metadata options: doesn't require HttpTokens while HttpEndpoint enabled`, region, instance.InstanceId);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
