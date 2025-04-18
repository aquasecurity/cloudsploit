'use strict';

module.exports = {
    title: 'Huawei VPC Security Groups',
    category: 'VPC',
    description: 'Ensures VPC security groups are properly configured.',
    apis: ['ListVpcs'],
    check: function(collection, callback) {
        var results = [];
        if (!collection.vpcs || !collection.vpcs.length) {
            results.push({
                resource: 'N/A',
                region: 'global',
                status: 0,
                message: 'No VPCs found'
            });
        } else {
            collection.vpcs.forEach(function(vpc) {
                results.push({
                    resource: vpc.id,
                    region: 'global',
                    status: 0,
                    message: 'Security group check not implemented yet'
                });
            });
        }
        callback(null, results);
    }
};
