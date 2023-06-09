var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Public Subnet',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensures EC2 instance is not deployed on public subnet',
    more_info: 'EC2 instances should not be deployed in public subnets to prevent direct exposure to the Internet and reduce the risk of unauthorized access.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-launch-instance-wizard.html#liw-network-settings',
    recommended_action: 'Re-lanuch the EC2 instance within the right subnet.',
    apis: ['EC2:describeInstances', 'EC2:describeRouteTables'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(cache, source, ['ec2', 'describeInstances', region]);
            var describeRouteTables = helpers.addSource(cache, source, ['ec2', 'describeRouteTables', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3, `Unable to query for instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            if (!describeRouteTables || !describeRouteTables.data || describeRouteTables.err) {
                helpers.addResult(results, 3, 'Unable to query for RouteTables: ' + helpers.addError(describeRouteTables), region);
                return rcb();
            }

            var publicSubnetIds = [];
            var vpc=[];


            describeRouteTables.data.forEach(function(routeTable) {
                routeTable.Routes.forEach(function(route) {
                    if (route.DestinationCidrBlock === '0.0.0.0/0' && route.GatewayId !== 'local') {
                        routeTable.Associations.forEach(function(association) {
                            if (association.Main === false) {
                                const { SubnetId } = association;
                                publicSubnetIds.push(SubnetId);
                            } else {
                                vpc.push(routeTable.VpcId);
                            }
                        });
                    }
                });
            });

            for (var instances of describeInstances.data) {
                const { OwnerId } = instances;
            
                for (var instance of instances.Instances) {
                    const { InstanceId, SubnetId, VpcId} = instance;
                    const resource = `arn:aws:ec2:${region}:${OwnerId}:instance/${InstanceId}`;
            
                    if (publicSubnetIds.includes(SubnetId) || vpc.includes(VpcId)) {
                        helpers.addResult(results, 2, 'EC2 instance is deployed on public subnet: ' + resource, region);
                    } else {
                        helpers.addResult(results, 0, 'EC2 instance is not deployed on public subnet: ' + resource, region);
                    }          
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
  

