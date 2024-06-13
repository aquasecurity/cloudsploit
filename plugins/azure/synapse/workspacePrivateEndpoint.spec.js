var expect = require('chai').expect;
var workspacePrivateEndpoint = require('./workspacePrivateEndpoint');

const workspaces = [
    {
        type: "Microsoft.Synapse/workspaces",
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        location: "eastus",
        name: "test",
        azureADOnlyAuthentication: true,
        privateEndpointConnections: [{
            id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test/privateEndpointConnections/test-endpoint-synapse-123",
            properties: {
            privateEndpoint: {
                id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Network/privateEndpoints/test-endpoint-synapse",
            },
            privateLinkServiceConnectionState: {
                status: "Approved",
            },
        },
    }],
    },
    {
        type: "Microsoft.Synapse/workspaces",
        id: "/subscriptions/123/resourceGroups/rsgrp/providers/Microsoft.Synapse/workspaces/test",
        location: "eastus",
        name: "test",
        privateEndpointConnections: []
    },
];


const createCache = (workspaces, err) => {

    return {
        synapse: {
            listWorkspaces: {
                'eastus': {
                    data: workspaces,
                    err: err
                }
            }
        }
    };
};

describe('workspacePrivateEndpoint', function () {
    describe('run', function () {

        it('should give a passing result if no Synapse workspaces are found', function (done) {
            const cache = createCache([], null);
            workspacePrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Synapse workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Synapse workspaces', function (done) {
            const cache = createCache(null, ['error']);
            workspacePrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Synapse workspaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if workspace has Private endpoints configured ', function (done) {
            const cache = createCache([workspaces[0]], null);
            workspacePrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private endpoints are configured for the Synapse workspace');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if workspace does not have Private endpoints configured', function (done) {
            const cache = createCache([workspaces[1]], null);
            workspacePrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Private endpoints are not configured for the Synapse workspace');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});