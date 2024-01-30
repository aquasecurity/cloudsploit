var expect = require('chai').expect;
var publicIpDdosProtectionEnabled = require('./publicIpDdosProtectionEnabled');

const publicIpAddresses = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/publicIpAddresses/test-vnet',
        "type": 'Microsoft.Network/publicIpAddresses',
        "location": 'eastus',
        "ddosSettings": {
            "protectionMode": "Enabled"
        }

    },
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/publicIpAddresses/test-vnet',
        "type": 'Microsoft.Network/publicIpAddresses',
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "ddosSettings": {
            "protectionMode": "VirtualNetworkInherited"
        }
    },
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/publicIpAddresses/test-vnet',
        "type": 'Microsoft.Network/publicIpAddresses',
        "location": 'eastus',
        "provisioningState": 'Succeeded',
    }
];

const createCache = (publicIpAddresses) => {
    return {
        publicIpAddresses: {
            list: {
                'eastus': {
                    data: publicIpAddresses
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        publicIpAddresses: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('publicIpDdosProtectionEnabled', function () {
    describe('run', function () {
        it('should give passing result if no Public Ip Addresses found', function (done) {
            const cache = createCache([]);
            publicIpDdosProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Public IP Addresses found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Public Ip Address does not have DDoS ip protection enabled', function (done) {
            const cache = createCache([publicIpAddresses[1]]);
            publicIpDdosProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Public IP Address does not have IP specific DDoS protection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Public Ip Address does not have DDoS ip protection enabled in case of default value', function (done) {
            const cache = createCache([publicIpAddresses[2]]);
            publicIpDdosProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Public IP Address does not have IP specific DDoS protection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Public Ip Addresses found', function (done) {
            const cache = createErrorCache();
            publicIpDdosProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Public IP Addresses:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Public Ip Address has DDoS ip protection enabled', function (done) {
            const cache = createCache([publicIpAddresses[0]]);
            publicIpDdosProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Public IP Address has IP specific DDoS protection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 