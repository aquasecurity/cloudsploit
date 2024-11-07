var expect = require('chai').expect;
var rgHasTags = require('./rgHasTags');

const resourceGroups = [
    {
        'name': 'test-rg',
        'id': '/subscriptions/123/resourceGroups/test1',
        'type': 'Microsoft.Resources/resourceGroups',
        'tags': { 'key': 'value'}
    },
    {
        'name': 'test-rg',
        'id': '/subscriptions/123/resourceGroups/test1',
        'type': 'Microsoft.Resources/resourceGroups',
    }
];

const createCache = (resourceGroups) => {
    return {
        resourceGroups: {
            list: {
                'eastus': {
                    data: resourceGroups
                } 
                    
            },
        }
    };
};

describe('rgHasTags', function() {
    describe('run', function() {
        it('should give passing result if no resource group', function(done) {
            const cache = createCache([]);
            rgHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing resource groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for resource group', function(done) {
            const cache = createCache(null);
            rgHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for resource groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Resource group has tags', function(done) {
            const cache = createCache([resourceGroups[0]]);
            rgHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Resource group has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Resource group does not have tags', function(done) {
            const cache = createCache([resourceGroups[1]]);
            rgHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Resource group does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});