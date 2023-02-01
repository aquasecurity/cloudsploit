var expect = require('chai').expect;
var vmScaleSetHasTags = require('./vmScaleSetHasTags');

const vmScaleSet = [
    { "name": 'test',
      "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachineScaleSets/test",
      "type": "Microsoft.Compute/virtualMachineScaleSets",
      "location": "centralus",
      "tags": {
        "key" : "value"
      }
    },
    { "name": 'test',
      "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachineScaleSets/test",
      "type": "Microsoft.Compute/virtualMachineScaleSets",
      "location": "centralus",
      "tags": {}
    },
];

const createCache = (vmScaleSet) => {
    return {
        vmScaleSet: {
            listAll: {
                'eastus': {
                    data: vmScaleSet
                }
            }
        }
    };
};

describe('vmScaleSetHasTags', function() {
    describe('run', function() {
        it('should give passing result if no scale set found', function(done) {
            const cache = createCache([]);
            vmScaleSetHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing VM scale sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for scale set', function(done) {
            const cache = createCache();
            vmScaleSetHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for VM scale sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if scale set has tags', function(done) {
            const cache = createCache([vmScaleSet[0]]);
            vmScaleSetHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM scale set has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VM scale set does not have tags', function(done) {
            const cache = createCache([vmScaleSet[1]]);
            vmScaleSetHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM scale set does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});