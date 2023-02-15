var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Associated With Default Security Group',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that AWS EC2 Instances are not associated with default security group.',
    more_info: 'The default security group is often used for resources launched without a defined security group. For this reason, deafult security groups should not be associated with ec2 instances.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group',
    recommended_action: 'Modify EC2 instances and change security group.',
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
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            for (var instances of describeInstances.data){
                const { OwnerId } = instances;

                for (var instance of instances.Instances) {
                    const { SecurityGroups, InstanceId } = instance;
                    console.log(SecurityGroups)
                    const arn = `arn:aws:ec2:${region}:${OwnerId}:instance/${InstanceId}`;
                    for (let sg of SecurityGroups) {
                        if (sg.GroupName === "default") {
                            helpers.addResult(results, 2, 'EC2 instance is associated with default security group', region, arn);
                        } else {
                            helpers.addResult(results, 0, 'EC2 instance is not associated with default security group', region, arn);
                        }
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
