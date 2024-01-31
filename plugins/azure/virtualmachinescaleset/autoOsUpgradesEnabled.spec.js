var expect = require('chai').expect;
var plugin = require('./autoOsUpgradesEnabled');

const createCache = (err, list) => {
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('autoOsUpgradesEnabled', function() {
    describe('run', function() {
        it('should give unknown result if unable to query for Virtual Machine Scale Sets', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                ['error'],
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no existing Virtual Machine Scale Sets found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if automatic OS upgrades feature is enabled for virtual machine scale set', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Automatic OS upgrades feature is enabled for virtual machine scale set')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/123/AQUA-RG/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-1",
                        "type": "Microsoft.Compute/virtualMachineScaleSets",
                        "location": "West US",
                        "upgradePolicy": {
                            "mode": "Automatic",
                            "automaticOSUpgradePolicy": {
                                "enableAutomaticOSUpgrade": true
                            }
                        }
                    },
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if automatic OS upgrades feature is not enabled for virtual machine scale set', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Automatic OS upgrades feature is not enabled for virtual machine scale set')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/123/AQUA-RG/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-1",
                        "type": "Microsoft.Compute/virtualMachineScaleSets",
                        "location": "West US",
                        "upgradePolicy": {
                            "mode": "Manual",
                        }
                    },
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})