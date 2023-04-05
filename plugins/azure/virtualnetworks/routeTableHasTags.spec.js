var expect = require('chai').expect;
var routeTableHasTags = require('./routeTableHasTags');

const RouteTables = [
    {
        "name": "testrt",
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/routeTables/testrt",
        "type": "Microsoft.Network/routeTables",
        "location": "westus",
        "tags": { "key": "value" },
    },
    {
        "name": "testrt2",
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/routeTables/testrt",
        "type": "Microsoft.Network/routeTables",
        "location": "westus",
        "tags": {},
    }
];

const createCache = (rt) => {
    return {
        routeTables: {
            listAll: {
                'eastus': {
                    data: rt
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        routeTables: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('routeTableHasTags', function() {
    describe('run', function() {
        it('should give passing result if no route table found', function(done) {
            const cache = createCache([]);
            routeTableHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Route table found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if route table does not have tags associated', function(done) {
            const cache = createCache([RouteTables[1]]);
            routeTableHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Route table does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Virtual Networks', function(done) {
            const cache = createErrorCache();
            routeTableHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for route tables:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if route table has tags associated', function(done) {
            const cache = createCache([RouteTables[0]]);
            routeTableHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Route table has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 