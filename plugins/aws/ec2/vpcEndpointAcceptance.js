var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC PrivateLink Endpoint Acceptance Required',
    category: 'EC2',
    description: 'Ensures VPC PrivateLink endpoints require acceptance',
    more_info: 'VPC PrivateLink endpoints should be configured to require acceptance so that access to the endpoint is controlled on a case-by-case basis.',
    recommended_action: 'Update the VPC PrivateLink endpoint to require acceptance',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/accept-reject-endpoint-requests.html',
    apis: ['EC2:describeVpcEndpointServices', 'EC2:describeVpcEndpointServicePermissions'],
    settings: {
        allow_blank_whitelisted_principals: {
            name: 'Allow If no Whitelisted Principals found',
            description: 'When set to true, VPC PrivateLink endpoints having zero/blank whitelisted pricipals will PASS',
            regex: '^(true|false)$',
            default: 'false'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultPartition = helpers.defaultPartition(settings);

        var config = {
            allow_blank_whitelisted_principals: settings.allow_blank_whitelisted_principals || this.settings.allow_blank_whitelisted_principals.default
        };

        config.allow_blank_whitelisted_principals = (config.allow_blank_whitelisted_principals == 'true');

        async.each(regions.ec2, function(region, rcb){
            var describeVpcEndpointServices = helpers.addSource(cache, source,
                ['ec2', 'describeVpcEndpointServices', region]);

            if (!describeVpcEndpointServices) return rcb();

            if (describeVpcEndpointServices.err || !describeVpcEndpointServices.data) {
                helpers.addResult(results, 3,
                    `Unable to query for VPC endpoint services: ${helpers.addError(describeVpcEndpointServices)}`, region);
                return rcb();
            }

            describeVpcEndpointServices.data = describeVpcEndpointServices.data.filter(service => service.Owner != 'amazon');

            if (!describeVpcEndpointServices.data.length) {
                helpers.addResult(results, 0,
                    'No user owned VPC endpoint services present', region);
                return rcb();
            }

            for (var service of describeVpcEndpointServices.data) {
                if (!service.ServiceId) continue;

                var resource = `arn:${defaultPartition}:ec2:${region}:${service.Owner}:vpc-endpoint-service/${service.ServiceId}`;

                if (service.AcceptanceRequired) {
                    helpers.addResult(results, 0,
                        `VPC endpoint service ${service.ServiceId} requires acceptance by the service owner`,
                        region, resource);
                } else {
                    if (config.allow_blank_whitelisted_principals) {
                        var describeVpcEndpointServicePermissions = helpers.addSource(cache, source,
                            ['ec2', 'describeVpcEndpointServicePermissions', region, service.ServiceId]);

                        if (!describeVpcEndpointServicePermissions ||
                            describeVpcEndpointServicePermissions.err ||
                            !describeVpcEndpointServicePermissions.data) {
                            helpers.addResult(results, 3,
                                `Unable to query VPC endpoint service permissions: ${describeVpcEndpointServicePermissions}`,
                                region, resource);
                            continue;
                        }

                        if (!describeVpcEndpointServicePermissions.data.AllowedPrincipals ||
                            !describeVpcEndpointServicePermissions.data.AllowedPrincipals.length) {
                            helpers.addResult(results, 0,
                                `VPC endpoint service ${service.ServiceId} does not require acceptance by the service owner but no allowed principals found`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `VPC endpoint service ${service.ServiceId} does not require acceptance by the service owner for allowed principals`,
                                region, resource);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            `VPC endpoint service ${service.ServiceId} does not require acceptance by the service owner`,
                            region, resource);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
