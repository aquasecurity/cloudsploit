var expect = require('chai').expect;
var desiredSkuSize = require('./desiredSkuSize');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'hardwareProfile': {
            'vmSize': 'Standard_DS3_v2'
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'hardwareProfile': {
            'vmSize': 'Standard_B1ls'
        }
    }
];

const createCache = (virtualMachines) => {
    let machine = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machine
            }
        }
    };
};

describe('desiredSkuSize', function() {
    describe('run', function() {
        it('should not run plugin if no size defined in setting', function(done) {
            const cache = createCache([]);
            desiredSkuSize.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            desiredSkuSize.run(cache, { vm_desired_sku_size: 'standard_ds3_v2'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            desiredSkuSize.run(cache, { vm_desired_sku_size: 'standard_ds3_v2'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if virtual machine is of desired SKU size', function(done) {
            const cache = createCache([virtualMachines[0]]);
            desiredSkuSize.run(cache, { vm_desired_sku_size: 'standard_ds3_v2'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual machine is using the desired SKU size of \'standard_ds3_v2\'');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if virtual machine is not of desired sku size', function(done) {
            const cache = createCache([virtualMachines[1]]);
            desiredSkuSize.run(cache, { vm_desired_sku_size: 'standard_ds3_v2'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual machine is not using the desired SKU size of \'standard_ds3_v2\'');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 
