'use strict';

module.exports = {
    title: 'Huawei VPC Open Ports',
    category: 'VPC',
    description: 'Checks for VPCs with open ports that may pose security risks.',
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
                    message: 'No open ports check implemented yet'
                });
            });
        }
        callback(null, results);
    }
};
