// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 has Tags',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure EC2 Instances have tags',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html',
    recommended_action: 'Add tags for ec2 instance',
    apis: ['EC2:describeInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(
                cache, source, ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3, `Unable to query for instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }
            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }
            for(var instances of describeInstances.data){
                const { OwnerId } = instances;
                for(var instance of instances.Instances){
                
                    const { Tags, InstanceId } = instance;
                    const ARN = `arn:aws:ec2:${region}:${OwnerId}:instance/${InstanceId}`;
                    if(Tags.length === 0){
                        helpers.addResult(results, 2, 'EC2 Instance has no tags', region, ARN);
                    }else {
                        helpers.addResult(results, 0, 'EC2 Instance has tags specified', region, ARN);
                    }
                }
            }
            
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
