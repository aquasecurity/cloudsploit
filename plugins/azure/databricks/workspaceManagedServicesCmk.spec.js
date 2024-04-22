var expect = require('chai').expect;
var workspaceManagedServicesCmk = require('./workspaceManagedServicesCmk.js');

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
        "encryption": {
            "entities": {
              "managedServices": {
                "keySource": "Microsoft.Keyvault",
                "keyVaultProperties": {
                  "keyVaultUri": "https://test.vault.azure.net",
                  "keyName": "test",
                  "keyVersion": "1"
                }
              },
            }
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

describe('workspaceManagedServicesCmk', function () {
    describe('run', function () {

        it('should give a passing result if no Databricks workspaces are found', function (done) {
            const cache = createCache([], null);
            workspaceManagedServicesCmk.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Databricks Workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Databricks workspaces', function (done) {
            const cache = createCache(null, ['error']);
            workspaceManagedServicesCmk.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Databricks Workspaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    
        it('should give passing result if workspace is not using premium tier', function (done) {
            const cache = createCache([workspaces[0]], null);
            workspaceManagedServicesCmk.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Databricks workspace is not a premium workspace');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Databricks workspace managed services has CMK encryption enabled', function (done) {
            const cache = createCache([workspaces[1]], null);
            workspaceManagedServicesCmk.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Databricks workspace managed services has CMK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Databricks workspace managed services does not have CMK encryption enabled', function (done) {
            const cache = createCache([workspaces[2]], null);
            workspaceManagedServicesCmk.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Databricks workspace managed services does not have CMK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});