var expect = require('chai').expect;
var workspaceHasTags = require('./workspaceHasTags.js');

const workspaces = [
    {
       "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Databricks/workspaces/test-workspace",
       "name": "test-workspace",
       "type": "Microsoft.Databricks/workspaces",
       "sku": {
         "name": "trial"
       },
       "location": "eastus",
       "tags": {}
    },
    {
       "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Databricks/workspaces/test-workspace",
       "name": "test-workspace",
       "type": "Microsoft.Databricks/workspaces",
       "sku": {
         "name": "premium"
       },
       "location": "eastus",
       "tags": {"key": "value"},
    },
];


const createCache = (workspaces, err) => {

    return {
        databricks: {
            listWorkspaces: {
                'eastus': {
                    data: workspaces,
                    err: err
                }
            }
        }
    };
};

describe('workspaceHasTags', function () {
    describe('run', function () {

        it('should give a passing result if no Databricks workspaces are found', function (done) {
            const cache = createCache([], null);
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Databricks Workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Databricks workspaces', function (done) {
            const cache = createCache(null, ['error']);
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Databricks Workspaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Databricks workspace has tags associated', function (done) {
            const cache = createCache([workspaces[1]], null);
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Databricks workspace has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Databricks workspace does not have tags associated', function (done) {
            const cache = createCache([workspaces[0]], null);
            workspaceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Databricks workspace does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});