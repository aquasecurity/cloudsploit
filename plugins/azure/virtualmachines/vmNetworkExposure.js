var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Internet Exposure',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Info',
    description: 'Check if Azure virtual machines are exposed to the internet.',
    more_info: 'Virtual machines exposed to the internet are at a higher risk of unauthorized access, data breaches, and cyberattacks. It’s crucial to limit exposure by securing access through proper configuration of security group and firewall rules.',
    link: 'https://learn.microsoft.com/en-us/azure/security/fundamentals/virtual-machines-overview',
    recommended_action: 'Secure VM instances by restricting access with properly configured security group and firewall rules.',
    apis: ['virtualMachines:listAll', 'networkInterfaces:listAll', 'networkSecurityGroups:listAll', 'virtualNetworks:listAll', 'loadBalancers:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachines:write', 'microsoftnetwork:networkinterfaces:write', 'microsoftcompute:virtualmachines:delete', 'microsoftnetwork:networkinterfaces:delete', 'microsoftnetwork:networksecuritygroups:write','microsoftnetwork:networksecuritygroups:delete', 'microsoftnetwork:virtualnetworks:write','microsoftnetwork:virtualnetworks:delete','microsoftnetwork:loadbalancers:write', 'microsoftnetwork:loadbalancers:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualMachines, function(location, rcb) {
            var virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtualMachines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            var networkInterfaces = helpers.addSource(cache, source,
                ['networkInterfaces', 'listAll', location]);

            if (!networkInterfaces || networkInterfaces.err || !networkInterfaces.data || !networkInterfaces.data.length) {
                helpers.addResult(results, 3, 'Unable to query for network interfaces: ' + helpers.addError(networkInterfaces), location);
                return rcb();
            }

            let networkSecurityGroups = helpers.addSource(cache, source,
                ['networkSecurityGroups', 'listAll', location]);


            if (!networkSecurityGroups || networkSecurityGroups.err || !networkSecurityGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for Network Security Groups: ' + helpers.addError(networkSecurityGroups), location);
                return rcb();
            }

            var virtualNetworks = helpers.addSource(cache, source,
                ['virtualNetworks', 'listAll', location]);


            virtualMachines.data.forEach(virtualMachine => {
                let vm_interfaces =  [];
                let securityGroups = [];
                let loadBalancers = [];
                if (virtualMachine.networkProfile && virtualMachine.networkProfile.networkInterfaces &&
                    virtualMachine.networkProfile.networkInterfaces.length > 0) {
                    let interfaceIDs =  virtualMachine.networkProfile.networkInterfaces.map(nic => nic.id);
                    vm_interfaces = networkInterfaces.data.filter(nic => interfaceIDs.includes(nic.id));
                    if (networkSecurityGroups && networkSecurityGroups.data && networkSecurityGroups.data.length) {
                        let securityGroupIDs =  vm_interfaces.filter(interface => interface.networkSecurityGroup && interface.networkSecurityGroup.id).map(nic => nic.networkSecurityGroup.id);
                        let allSubnetIDs = vm_interfaces.reduce((acc, nic) => {
                            let subnetIds = nic.ipConfigurations.map(ipConfig => ipConfig.properties.subnet.id);
                            return acc.concat(subnetIds);
                        }, []);

                        if (virtualNetworks && !virtualNetworks.err && virtualNetworks.data && virtualNetworks.data.length) {
                            virtualNetworks.data.forEach(vnet => {
                                if (vnet.subnets && vnet.subnets.length) {
                                    vnet.subnets.forEach(subnet => {
                                        if (allSubnetIDs.includes(subnet.id) && subnet.properties && subnet.properties.networkSecurityGroup && subnet.properties.networkSecurityGroup.id) {
                                            securityGroupIDs.push(subnet.properties.networkSecurityGroup.id);
                                        }
                                    });
                                }
                            });

                        }
                        securityGroups = networkSecurityGroups.data.filter(nsg => securityGroupIDs.includes(nsg.id));
                    }

                    // get load balancers
                    for (let nic of vm_interfaces) {
                        if (nic.ipConfigurations && nic.ipConfigurations.length) {
                            nic.ipConfigurations.map(ipConfig => {
                                if (ipConfig.properties) {
                                    if (ipConfig.properties.loadBalancerInboundNatRules && ipConfig.properties.loadBalancerInboundNatRules.length) {
                                        ipConfig.properties.loadBalancerInboundNatRules.forEach(rule => {
                                            let id = rule.id;
                                            let match = id.match(/\/subscriptions\/.+?(?=\/inboundNatRules)/);

                                            if (match && match[0]) {
                                                if (!loadBalancers.includes(match[0])) {
                                                    loadBalancers.push(match[0]);
                                                }
                                            }
                                        });
                                    }
                                    if (ipConfig.properties.loadBalancerBackendAddressPools && ipConfig.properties.loadBalancerBackendAddressPools.length) {
                                        ipConfig.properties.loadBalancerBackendAddressPools.forEach(pool => {
                                            let id = pool.id;
                                            let match = id.match(/\/subscriptions\/.+?(?=\/backendAddressPools)/);
                                            if (match && match[0]) {
                                                if (!loadBalancers.includes(match[0])) {
                                                    loadBalancers.push(match[0]);
                                                }
                                            }
                                        });
                                    }
                                }
                            });
                        }
                    }
                }
                let internetExposed =  helpers.checkNetworkExposure(cache, source, vm_interfaces, securityGroups, location, results, {lbNames: loadBalancers}, virtualMachine);
                if (internetExposed && internetExposed.length) {
                    helpers.addResult(results, 2, `VM is exposed to the internet through ${internetExposed}`, location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 0, 'VM is not exposed to the internet', location, virtualMachine.id);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
