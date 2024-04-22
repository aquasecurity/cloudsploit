var expect = require('chai').expect;
var databricksWorkspaceInfraEncryption = require('./workspaceDbfsInfraEncryption.js');

const workspaces = [
    {
        "managedResourceGroupId": "/subscriptions/1234/resourceGroups/test",
        "parameters": {
          "requireInfrastructureEncryption": {
            "type": "Bool",
            "value": false
          },
        },
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
        "managedResourceGroupId": "/subscriptions/1234/resourceGroups/test",
        "parameters": {
          "requireInfrastructureEncryption": {
            "type": "Bool",
            "value": true
          },
        },
       "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Databricks/workspaces/test-workspace",
       "name": "test-workspace",
       "type": "Microsoft.Databricks/workspaces",
       "sku": {
         "name": "premium"
       },
       "location": "eastus",
       "tags": {}
    },
    {
        "managedResourceGroupId": "/subscriptions/1234/resourceGroups/test",
        "parameters": {
          "requireInfrastructureEncryption": {
            "type": "Bool",
            "value": false
          },
        },
       "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Databricks/workspaces/test-workspace",
       "name": "test-workspace",
       "type": "Microsoft.Databricks/workspaces",
       "sku": {
         "name": "premium"
       },
       "location": "eastus",
       "tags": {}
    }
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

describe('databricksWorkspaceInfraEncryption', function () {
    describe('run', function () {

        it('should give a passing result if no Databricks workspaces are found', function (done) {
            const cache = createCache([], null);
            databricksWorkspaceInfraEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Databricks Workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Databricks workspaces', function (done) {
            const cache = createCache(null, ['error']);
            databricksWorkspaceInfraEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Databricks Workspaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    
        it('should give passing result if workspace is not using premium tier', function (done) {
            const cache = createCache([workspaces[0]], null);
            databricksWorkspaceInfraEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Databricks workspace is not a premium workspace');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if workspace dbfs root has infrastructure level encryption enabled', function (done) {
            const cache = createCache([workspaces[1]], null);
            databricksWorkspaceInfraEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DBFS root storage for databricks workspace has infrastructure level encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Databricks workspace DBFS root does not have infrastructure level encryption enabled', function (done) {
            const cache = createCache([workspaces[2]], null);
            databricksWorkspaceInfraEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DBFS root storage for databricks workspace does not have infrastructure level encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});