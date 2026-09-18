module.exports = {
    title: 'Huawei VPC Flow Logs Enabled',
    category: 'VPC',
    description: 'Checks if VPC flow logs are enabled for monitoring.',
    apis: ['ListVpcs'],
    check: function(collection, callback) {
        //console.log('DEBUG: vpcFlowLogsEnabled plugin called with collection:', JSON.stringify(collection, null, 2));
        const results = [];

        if (!collection.vpcs || !collection.vpcs.vpcs || !collection.vpcs.vpcs.length) {
            results.push({
                resource: 'N/A',
                region: 'global',
                status: 0,
                message: 'No VPCs found'
            });
        } else {
            collection.vpcs.vpcs.forEach(vpc => {
                const flowLogsEnabled = vpc.enable_flow_log || false;
                results.push({
                    resource: vpc.id,
                    region: 'global',
                    status: flowLogsEnabled ? 0 : 2, // 0 = PASS, 2 = FAIL
                    message: flowLogsEnabled ? 'VPC flow logs are enabled' : 'VPC flow logs are not enabled'
                });
            });
        }

        //console.log('DEBUG: vpcFlowLogsEnabled results:', results);
        callback(null, results);
    }
};
