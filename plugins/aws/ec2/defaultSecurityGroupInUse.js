var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Default Security Group In Use',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that AWS EC2 Instances are not associated with default security group.',
    more_info: 'The default security group allows all traffic inbound and outbound, which can make your resources vulnerable to attacks. Ensure that the Amazon EC2 instances are not associated with the default security groups.',
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
                    const { InstanceId } = instance;
                    const arn = `arn:aws:ec2:${region}:${OwnerId}:instance/${InstanceId}`;
                    const defaultSecurityGroup = (instance.SecurityGroups && instance.SecurityGroups.length) ? instance.SecurityGroups.find(sg => sg.GroupName.toLowerCase() == 'default'): false;
                    if (defaultSecurityGroup) {
                        helpers.addResult(results, 2, 'EC2 instance is associated with default security group', region, arn);
                    } else {
                        helpers.addResult(results, 0, 'EC2 instance is not associated with default security group', region, arn);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
