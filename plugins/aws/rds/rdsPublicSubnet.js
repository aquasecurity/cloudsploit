var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Public Subnet',
    category: 'RDS',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures RDS database instances are not deployed in public subnet.',
    more_info: 'RDS instances should not be deployed in public subnets to prevent direct exposure to the internet and reduce the risk of unauthorized access.',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-subnet-igw-check.html',
    recommended_action: 'Replace the subnet groups of rds instance with the private subnets.',
    apis: ['RDS:describeDBInstances', 'EC2:describeRouteTables', 'EC2:describeSubnets'],
    realtime_triggers: ['rds:CreateDBInstance', 'rds:ModifyDBInstance', 'rds:RestoreDBInstanceFromDBSnapshot', 'rds:RestoreDBInstanceFromS3','rds:DeleteDBInstance'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instances found', region);
                return rcb();
            }

            var describeRouteTables = helpers.addSource(cache, {},
                ['ec2', 'describeRouteTables', region]);   
            var describeSubnets = helpers.addSource(cache, source,
                ['ec2', 'describeSubnets', region]);

            if (!describeSubnets || describeSubnets.err || !describeSubnets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for subnets: ' + helpers.addError(describeSubnets), region);
                return rcb();                  
            } 

            if (!describeRouteTables || !describeRouteTables.data || describeRouteTables.err) {
                helpers.addResult(results, 3, 'Unable to query for RouteTables: ' + helpers.addError(describeRouteTables), region);
                return rcb();
            } 
            var subnetRouteTableMap;
            var privateSubnets = [];
            subnetRouteTableMap = helpers.getSubnetRTMap(describeSubnets.data, describeRouteTables.data);
            privateSubnets = helpers.getPrivateSubnets(subnetRouteTableMap, describeSubnets.data, describeRouteTables.data);  

            describeDBInstances.data.forEach(instance => {
                if (!instance.DBInstanceArn ) return;

                const dbResource = instance.DBInstanceArn;
                const subnetsData = instance.DBSubnetGroup.Subnets;
                const allPrivate = subnetsData.every(subnet => privateSubnets.includes(subnet.SubnetIdentifier));

                if (allPrivate) {
                    helpers.addResult(results, 0, 'RDS instance is not in a public subnet', region, dbResource);
                } else { 
                    helpers.addResult(results, 2, 'RDS instance is in a public subnet', region, dbResource);
                }        
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
